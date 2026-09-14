/* ============================================================
   KW66 Morse Messenger v4.0
   Чистый мессенджер поверх ранее подтверждённого протокола KW66:
   - D1 09/07/08 = ввод по Морзе (Previous/Play/Next)
   - 0xC5 = произвольный текст на экран часов
   Всё, что не нужно мессенджеру (HR/шаги/фаззер/протокол-лабы),
   сознательно убрано — см. app.js предыдущей версии в архиве, если
   понадобится вернуть диагностику.

   Крипто-модель:
   - Постоянная identity-пара ECDH P-256 на устройство, приватный
     ключ создаётся как extractable:false и хранится в IndexedDB как
     CryptoKey (не как экспортированные байты) — приватный ключ
     физически не существует вне защищённого хранилища браузера.
   - При pairing стороны обмениваются публичными ключами через
     Supabase (см. ниже) и считают общий секрет (ECDH) → HKDF-SHA256
     → сессионный AES-256-GCM ключ. Сессионный ключ никогда не
     сохраняется — пересчитывается заново на старте, если оба
     публичных ключа уже известны.
   - Fingerprint (SHA-256 от отсортированной пары публичных ключей)
     показывается пользователю один раз при pairing — сверка вручную
     защищает от подмены ключа на стороне сервера (Supabase видит
     только сами публичные ключи и не может её скрыть, если ты
     проверишь fingerprint на обоих устройствах).

   Транспорт: Supabase Realtime. Сервер видит только шифротекст и
   момент отправки; строка удаляется сразу после того, как получатель
   её забрал.
   ============================================================ */
"use strict";

/* ---------- утилиты ---------- */
const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));
function nowStr(){ return new Date().toLocaleTimeString(); }
function hex(bytes){ return [...bytes].map(x=>x.toString(16).padStart(2,"0").toUpperCase()).join(" "); }
function b64(bytes){ let s=""; for(const b of bytes) s+=String.fromCharCode(b); return btoa(s); }
function unb64(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
function log(s){
  const el=$("log");
  el.textContent += (el.textContent?"\n":"") + `[${nowStr()}] ${s}`;
  el.scrollTop=el.scrollHeight;
}

/* ============================================================
   IndexedDB — хранилище идентичности (CryptoKey сохраняется как
   объект, а не как экспортированные байты)
   ============================================================ */
const idb = {
  db:null,
  open(){
    if(this.db) return Promise.resolve(this.db);
    return new Promise((res,rej)=>{
      const req=indexedDB.open("kw66msg",1);
      req.onupgradeneeded=()=>req.result.createObjectStore("kv");
      req.onsuccess=()=>{ this.db=req.result; res(this.db); };
      req.onerror=()=>rej(req.error);
    });
  },
  async set(key,value){
    const db=await this.open();
    return new Promise((res,rej)=>{
      const tx=db.transaction("kv","readwrite");
      tx.objectStore("kv").put(value,key);
      tx.oncomplete=()=>res(); tx.onerror=()=>rej(tx.error);
    });
  },
  async get(key){
    const db=await this.open();
    return new Promise((res,rej)=>{
      const tx=db.transaction("kv","readonly");
      const r=tx.objectStore("kv").get(key);
      r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error);
    });
  },
  async del(key){
    const db=await this.open();
    return new Promise((res,rej)=>{
      const tx=db.transaction("kv","readwrite");
      tx.objectStore("kv").delete(key);
      tx.oncomplete=()=>res(); tx.onerror=()=>rej(tx.error);
    });
  }
};

/* ============================================================
   Крипто: ECDH P-256 (нативный Web Crypto, без внешних библиотек —
   универсальная поддержка в браузерах, без веса лишней JS-библиотеки
   в офлайн-кэше PWA) + HKDF-SHA256 + AES-256-GCM
   ============================================================ */
const HKDF_INFO = new TextEncoder().encode("kw66-morse-messenger-v1");

function compareBytes(a,b){
  for(let i=0;i<Math.min(a.length,b.length);i++){ if(a[i]!==b[i]) return a[i]-b[i]; }
  return a.length-b.length;
}
async function computeSalt(pubA,pubB){
  const [x,y]=compareBytes(pubA,pubB)<=0?[pubA,pubB]:[pubB,pubA];
  const combined=new Uint8Array(x.length+y.length); combined.set(x); combined.set(y,x.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256",combined));
}

const identity = {
  keyPair:null, peerPubRaw:null, peerPubKey:null, sessionKey:null, fingerprint:null,

  async ensureKeypair(){
    if(this.keyPair) return this.keyPair;
    const priv=await idb.get("identityPriv");
    const pub=await idb.get("identityPub");
    if(priv && pub){
      this.keyPair={privateKey:priv, publicKey:pub};
    } else {
      this.keyPair=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
      await idb.set("identityPriv",this.keyPair.privateKey);
      await idb.set("identityPub",this.keyPair.publicKey);
    }
    return this.keyPair;
  },
  async exportPubB64(){
    const raw=await crypto.subtle.exportKey("raw",this.keyPair.publicKey);
    return b64(new Uint8Array(raw));
  },
  async setPeerFromB64(str){
    this.peerPubRaw=unb64(str);
    this.peerPubKey=await crypto.subtle.importKey("raw",this.peerPubRaw,{name:"ECDH",namedCurve:"P-256"},false,[]);
    await idb.set("peerPub",this.peerPubRaw);
  },
  async restore(){
    const priv=await idb.get("identityPriv"), pub=await idb.get("identityPub");
    if(!priv||!pub) return false;
    this.keyPair={privateKey:priv,publicKey:pub};
    const peer=await idb.get("peerPub");
    const pairId=await idb.get("pairId"); const role=await idb.get("role");
    if(peer){
      this.peerPubRaw=peer;
      this.peerPubKey=await crypto.subtle.importKey("raw",peer,{name:"ECDH",namedCurve:"P-256"},false,[]);
      await this.deriveSession();
    }
    return {pairId,role,paired:!!peer};
  },
  async deriveSession(){
    const myPubRaw=new Uint8Array(await crypto.subtle.exportKey("raw",this.keyPair.publicKey));
    const bits=await crypto.subtle.deriveBits({name:"ECDH",public:this.peerPubKey},this.keyPair.privateKey,256);
    const salt=await computeSalt(myPubRaw,this.peerPubRaw);
    const km=await crypto.subtle.importKey("raw",bits,"HKDF",false,["deriveKey"]);
    this.sessionKey=await crypto.subtle.deriveKey(
      {name:"HKDF",hash:"SHA-256",salt,info:HKDF_INFO}, km, {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]
    );
    const fpDigest=await crypto.subtle.digest("SHA-256",salt);
    this.fingerprint=[...new Uint8Array(fpDigest).slice(0,5)].map(x=>x.toString(16).padStart(2,"0")).join(" ").toUpperCase();
    return this.sessionKey;
  },
  async encrypt(text){
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const data=new TextEncoder().encode(text);
    const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},this.sessionKey,data);
    return {iv:b64(iv), data:b64(new Uint8Array(cipher))};
  },
  async decrypt(packet){
    const iv=unb64(packet.iv), data=unb64(packet.data);
    const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},this.sessionKey,data);
    return new TextDecoder().decode(plain);
  },
  async forgetAll(){
    await idb.del("identityPriv"); await idb.del("identityPub");
    await idb.del("peerPub"); await idb.del("pairId"); await idb.del("role");
    location.reload();
  }
};

function randomInviteCode(){
  const chars="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // без похожих символов (0/O, 1/I)
  const bytes=crypto.getRandomValues(new Uint8Array(16));
  let s=""; for(const b of bytes) s+=chars[b % chars.length];
  return s.match(/.{1,4}/g).join("-"); // XXXX-XXXX-XXXX-XXXX, ~80 бит
}

/* ============================================================
   Транспорт: Supabase (Realtime + Postgres). Сервер видит только
   base64 шифротекст, iv и служебный pair_id (сам является одноразовым
   секретом-возможностью — см. схему в supabase-schema.sql).
   ============================================================ */
const relay = {
  client:null, channel:null, pairId:null, role:null,

  configured(){ return !!this.client; },
  init(url,key){ this.client=window.supabase.createClient(url,key); },

  async createInvite(){
    await identity.ensureKeypair();
    const pub=await identity.exportPubB64();
    const pairId=randomInviteCode();
    const {error}=await this.client.from("pairs").insert({id:pairId, pub_a:pub});
    if(error) throw error;
    this.pairId=pairId; this.role="a";
    await idb.set("pairId",pairId); await idb.set("role","a");
    return pairId;
  },
  // Инициатор ждёт, пока второй телефон положит свой публичный ключ в ту же строку.
  waitForPeerPub(pairId){
    return new Promise((resolve,reject)=>{
      const ch=this.client.channel("pairwait-"+pairId)
        .on("postgres_changes",{event:"UPDATE",schema:"public",table:"pairs",filter:`id=eq.${pairId}`},payload=>{
          if(payload.new.pub_b){ ch.unsubscribe(); resolve(payload.new.pub_b); }
        }).subscribe();
      setTimeout(()=>{ ch.unsubscribe(); reject(new Error("Таймаут ожидания второго устройства (10 мин)")); },10*60*1000);
    });
  },
  async joinWithCode(code){
    await identity.ensureKeypair();
    const {data,error}=await this.client.from("pairs").select("pub_a").eq("id",code).single();
    if(error||!data) throw new Error("Код приглашения не найден");
    const myPub=await identity.exportPubB64();
    const {error:upErr}=await this.client.from("pairs").update({pub_b:myPub}).eq("id",code);
    if(upErr) throw upErr;
    await identity.setPeerFromB64(data.pub_a);
    this.pairId=code; this.role="b";
    await idb.set("pairId",code); await idb.set("role","b");
    return data.pub_a;
  },
  async cleanupPairRow(pairId){
    try{ await this.client.from("pairs").delete().eq("id",pairId); }catch{}
  },
  subscribeMessages(onMessage){
    if(this.channel) this.channel.unsubscribe();
    this.channel=this.client.channel("relay-"+this.pairId)
      .on("postgres_changes",{event:"INSERT",schema:"public",table:"relay",filter:`pair_id=eq.${this.pairId}`},payload=>{
        const row=payload.new;
        if(row.from_role===this.role) return; // это наша же отправка, эхо от Realtime
        onMessage(row);
      }).subscribe();
  },
  async sendCiphertext(packet){
    const {error}=await this.client.from("relay").insert({pair_id:this.pairId, from_role:this.role, iv:packet.iv, ciphertext:packet.data});
    if(error) throw error;
  },
  async deleteRow(id){
    try{ await this.client.from("relay").delete().eq("id",id); }catch{}
  }
};

function setPairUi(paired){
  $("pairDot").classList.toggle("on",paired);
  $("pairStatus").textContent=paired?`пара установлена (${relay.role==="a"?"A":"B"})`:"пара не установлена";
  $("fpBox").style.display=paired?"block":"none";
  if(paired) $("fp").textContent=identity.fingerprint;
  $("pairSetup").style.display=paired?"none":"block";
}

async function establishPairing(pairId){
  await identity.deriveSession();
  relay.subscribeMessages(onIncomingMessage);
  setPairUi(true);
  log(`Пара установлена. Канал: ${pairId}. Сверь fingerprint на обоих устройствах.`);
}

/* ---------- получение сообщения: расшифровка целиком в памяти, сразу на часы ---------- */
async function onIncomingMessage(row){
  let text=null;
  try{
    text=await identity.decrypt({iv:row.iv, data:row.ciphertext});
    await sendWatchText(text);
    log("Сообщение получено и отправлено на часы.");
  }catch(e){
    log(`Ошибка расшифровки входящего сообщения: ${e.message}`);
  }finally{
    text=null; // явно освобождаем ссылку; нигде не логировалось и не рендерилось
    await relay.deleteRow(row.id);
  }
}

/* ============================================================
   BLE: подключение к KW66 (сохранён минимум из предыдущей версии —
   только то, что нужно для Морзе-ввода и отправки текста)
   ============================================================ */
const UUID = {
  service4:"000055ff-0000-1000-8000-00805f9b34fb",
  service5:"000056ff-0000-1000-8000-00805f9b34fb",
  tx4:"000033f1-0000-1000-8000-00805f9b34fb",
  rx4:"000033f2-0000-1000-8000-00805f9b34fb",
  tx5:"000034f1-0000-1000-8000-00805f9b34fb",
  rx5:"000034f2-0000-1000-8000-00805f9b34fb",
  txAlt:"0000b003-0000-1000-8000-00805f9b34fb",
  rxAlt:"0000b004-0000-1000-8000-00805f9b34fb"
};
let device=null, server=null, txChars=[], activeTx=null, rxBuffers={};

function setBleUi(connected){
  $("bleDot").classList.toggle("on",connected);
  $("bleStatus").textContent=connected?`подключено: ${device?.name||"KW66"}`:"не подключено";
}
async function connect(){
  if(!navigator.bluetooth){ log("Web Bluetooth недоступен (нужен Chrome/Android)."); return; }
  try{
    log("Поиск устройства…");
    device=await navigator.bluetooth.requestDevice({acceptAllDevices:true, optionalServices:[UUID.service4,UUID.service5]});
    device.addEventListener("gattserverdisconnected",()=>{
      log("GATT отключён."); server=null; txChars=[]; activeTx=null; rxBuffers={}; setBleUi(false);
    });
    server=await device.gatt.connect();
    log(`GATT подключён: ${device.name||"(без имени)"}`);
    const services=await server.getPrimaryServices();
    const chars=[];
    for(const s of services){ for(const c of await s.getCharacteristics()) chars.push(c); }
    txChars=chars.filter(c=>[UUID.tx4,UUID.tx5,UUID.txAlt].some(u=>u===c.uuid.toLowerCase()) && (c.properties?.write||c.properties?.writeWithoutResponse));
    const rxChars=chars.filter(c=>[UUID.rx4,UUID.rx5,UUID.rxAlt].some(u=>u===c.uuid.toLowerCase()) && (c.properties?.notify||c.properties?.indicate));
    activeTx=txChars[0]||null;
    for(const c of rxChars){
      await c.startNotifications();
      c.addEventListener("characteristicvaluechanged",e=>{
        const v=e.target.value;
        pushToBuffer(new Uint8Array(v.buffer.slice(v.byteOffset,v.byteOffset+v.byteLength)));
      });
    }
    setBleUi(!!activeTx);
    log(`Готово. TX=${txChars.length}, RX=${rxChars.length}.`);
  }catch(e){
    log(`Ошибка подключения: ${e.name||"Error"}: ${e.message||e}`);
  }
}
async function bleSend(bytes){
  if(!activeTx) throw new Error("Нет TX-канала (часы не подключены)");
  const u8=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
  if(activeTx.properties.writeWithoutResponse && !activeTx.properties.write) await activeTx.writeValueWithoutResponse(u8);
  else await activeTx.writeValue(u8);
}

/* ============================================================
   Сырой рекордер (диагностика): логирует каждый входящий D1-пакет
   как есть — байты + время + дельту от предыдущего события того же
   кода. Ничего не классифицирует, ни на что не влияет — работает
   параллельно с обычным вводом, чтобы понять реальное поведение
   часов (одно событие на клик / авто-повтор при удержании /
   отдельные коды нажатия и отпускания).
   ============================================================ */
const rawRec = {
  enabled:false, lastT:{}, startT:null,
  log(bytes){
    const t=performance.now();
    if(this.startT===null) this.startT=t;
    const code=bytes.length>=2?bytes[1]:null;
    const key=`${bytes[0]}:${code}`;
    const prev=this.lastT[key];
    const delta=prev!==undefined?Math.round(t-prev):null;
    this.lastT[key]=t;
    const el=$('rawLog');
    if(!el) return;
    const line=`t=${Math.round(t-this.startT)}ms  ${hex(bytes)}  ${delta!==null?`Δ=${delta}ms`:'(первое)'}`;
    el.textContent+=(el.textContent?'\n':'')+line;
    el.scrollTop=el.scrollHeight;
  },
  clear(){ this.lastT={}; this.startT=null; const el=$('rawLog'); if(el) el.textContent=''; }
};

/* ---------- сборка фрагментов D1/C5 (упрощено под нужды мессенджера) ---------- */
function pushToBuffer(bytes){
  if(bytes.length===0) return;
  if(rawRec.enabled) rawRec.log(bytes);
  const op=bytes[0];
  if(op===0xD1 && bytes.length>=2){ handleD1(bytes); return; }
  // C5 <seq> — квитанция куска текста от часов; для мессенджера не критична, просто пропускаем
}

/* ---------- 0xC5: произвольный текст на экран часов (протокол подтверждён ранее) ---------- */
function utf16beBytes(str){
  const out=new Uint8Array(str.length*2);
  for(let i=0;i<str.length;i++){ const cu=str.charCodeAt(i); out[i*2]=(cu>>8)&0xFF; out[i*2+1]=cu&0xFF; }
  return out;
}
async function sendWatchText(text,id=0x01){
  if(!text) return;
  const payload=utf16beBytes(text);
  const totalLen=payload.length & 0xFF;
  const CHUNK=18;
  let seq=0, off=0;
  const firstText=payload.slice(0,CHUNK-2);
  const p0=new Uint8Array(4+firstText.length);
  p0[0]=0xC5; p0[1]=seq; p0[2]=id&0xFF; p0[3]=totalLen; p0.set(firstText,4);
  await bleSend(p0);
  seq=(seq+1)%0xFD; off=firstText.length;
  while(off<payload.length){
    const chunk=payload.slice(off,off+CHUNK);
    const p=new Uint8Array(2+chunk.length);
    p[0]=0xC5; p[1]=seq; p.set(chunk,2);
    await bleSend(p);
    seq=(seq+1)%0xFD; off+=CHUNK;
    await sleep(40);
  }
  await bleSend([0xC5,0xFD]);
}

/* ============================================================
   Морзе-ввод (без изменений в логике распознавания из v3.13,
   диагностика/тестовые кнопки оставлены только в свёрнутом details)
   ============================================================ */
const MORSE_EN={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'};
const MORSE_RU={'.-':'А','-...':'Б','.--':'В','--.':'Г','-..':'Д','.':'Е','...-':'Ж','--..':'З','..':'И','.---':'Й','-.-':'К','.-..':'Л','--':'М','-.':'Н','---':'О','.--.':'П','.-.':'Р','...':'С','-':'Т','..-':'У','..-.':'Ф','....':'Х','---.':'Ц','----':'Ч','--.-':'Ш','--.--':'Щ','-.--':'Ы','-..-':'Ь','..-..':'Э','..--':'Ю','.-.-':'Я'};
const MORSE_MAP={...MORSE_EN,...MORSE_RU};
const MORSE_HOLD_MS=1200, MORSE_LONG_SUPPRESS_MS=1300, MORSE_DOUBLE_MS=550;

const morse={
  pattern:'', text:'', symbols:0, letters:0, debug:false,
  pendingPlay:null, pendingNext:null, playTimer:null, nextTimer:null, playSuppressUntil:0,
  setState(s){ $('morseState').textContent=s; },
  ui(){ $('morseSymbols').textContent=this.symbols; $('morseLetters').textContent=this.letters; },
  dbg(s){ if(this.debug){ const el=$('morseDebugOut'); el.style.display='block'; el.textContent+=(el.textContent?'\n':'')+`[${nowStr()}] ${s}`; el.scrollTop=el.scrollHeight; } },
  event(kind,source='test'){
    if(kind==='dot') this.pattern+='.';
    else if(kind==='dash') this.pattern+='-';
    else if(kind==='commit'){
      if(!this.pattern) return;
      const ch=MORSE_MAP[this.pattern]||'□';
      this.text+=ch; this.letters++; this.pattern='';
      this.dbg(`letter=${ch}`);
    }
    this.symbols++; $('morseLast').textContent=kind==='dot'?'·':kind==='dash'?'−':'Next';
    this.setState(kind==='commit'?'буква принята':'приём'); this.ui();
    this.dbg(`event ${kind} (${source}) pattern=${this.pattern||'∅'}`);
  },
  deleteLast(){
    if(this.pattern){ this.pattern=''; this.setState('удаление'); $('morseLast').textContent='⌫ буква'; this.ui(); return; }
    if(this.text){ const chars=[...this.text]; chars.pop(); this.text=chars.join(''); this.letters=Math.max(0,this.letters-1); }
    this.setState('удаление'); $('morseLast').textContent='⌫ буква'; this.ui();
  },
  space(){
    if(!this.text && !this.pattern) return;
    if(this.pattern) this.event('commit','auto before space');
    if(this.text && !this.text.endsWith(' ')){ this.text+=' '; this.letters++; this.symbols++; }
    $('morseLast').textContent='Пробел'; this.setState('пробел'); this.ui(); this.dbg('Next short → space');
  },
  reset(){
    clearTimeout(this.playTimer); clearTimeout(this.nextTimer);
    this.pendingPlay=null; this.pendingNext=null;
    this.pattern='';this.text='';this.symbols=0;this.letters=0;this.setState('ожидание');$('morseLast').textContent='—';this.ui();$('morseDebugOut').textContent='';this.dbg('reset');
  },
  async send(){
    if(!this.text) return;
    if(!identity.sessionKey){ log('Отправка невозможна: пара не установлена (см. раздел 2).'); return; }
    const plaintext=this.text;
    try{
      const packet=await identity.encrypt(plaintext);
      await relay.sendCiphertext(packet);
      this.setState('отправлено'); $('morseLast').textContent='отправлено';
      this.dbg(`отправлено, длина=${plaintext.length} символов; открытый текст нигде не сохранён`);
    }catch(e){
      log(`Ошибка отправки: ${e.message}`);
    }finally{
      this.text=''; this.pattern=''; this.letters=0; this.symbols=0; this.ui();
      setTimeout(()=>this.setState('ожидание'),900);
    }
  }
};

function handleD1(b){
  if(!b || b[0]!==0xD1 || b.length<2) return false;
  const code=b[1];
  if(code!==0x07 && code!==0x08 && code!==0x09) return false;
  const t=performance.now();

  if(code===0x07){ // Play/Pause: короткое=точка, длинное=тире
    if(t<morse.playSuppressUntil){ morse.dbg('D1 07 игнор (повтор long-press)'); return true; }
    if(morse.pendingPlay && (t-morse.pendingPlay.at)<=MORSE_HOLD_MS){
      clearTimeout(morse.playTimer); morse.pendingPlay=null;
      morse.playSuppressUntil=t+MORSE_LONG_SUPPRESS_MS;
      morse.event('dash','KW66 D1 07 long');
      return true;
    }
    if(morse.pendingPlay){ clearTimeout(morse.playTimer); morse.pendingPlay=null; }
    morse.pendingPlay={at:t};
    morse.playTimer=setTimeout(()=>{ if(!morse.pendingPlay) return; morse.pendingPlay=null; morse.event('dot','KW66 D1 07 short'); },MORSE_HOLD_MS);
    return true;
  }
  if(code===0x08){ // Next: пусто=пробел, дважды=отправить
    if(morse.pendingNext && (t-morse.pendingNext.at)<=MORSE_DOUBLE_MS){
      clearTimeout(morse.nextTimer); morse.pendingNext=null;
      morse.send().catch(e=>log(`Ошибка отправки: ${e.message}`));
      return true;
    }
    if(morse.pendingNext){ clearTimeout(morse.nextTimer); morse.pendingNext=null; }
    morse.pendingNext={at:t};
    morse.nextTimer=setTimeout(()=>{ if(!morse.pendingNext) return; morse.pendingNext=null; morse.space(); },MORSE_DOUBLE_MS);
    return true;
  }
  morse.deleteLast(); // Previous: удалить незавершённый символ/последнюю букву
  return true;
}

/* ============================================================
   Привязка UI
   ============================================================ */
$('connect').onclick=connect;
$('disconnect').onclick=async()=>{ try{ if(device?.gatt?.connected) device.gatt.disconnect(); }catch{} };
$('clearLog').onclick=()=>{ $('log').textContent=''; };

$('rawRecToggle').onchange=e=>{ rawRec.enabled=e.target.checked; if(rawRec.enabled) rawRec.clear(); };
$('rawRecClear').onclick=()=>rawRec.clear();

$('morseDebug').onchange=e=>{ morse.debug=e.target.checked; $('morseDebugOut').style.display=morse.debug?'block':'none'; };
$('morseTestDot').onclick=()=>morse.event('dot');
$('morseTestDash').onclick=()=>morse.event('dash');
$('morseTestCommit').onclick=()=>morse.event('commit');
$('morseSpace').onclick=()=>morse.space();
$('morseReset').onclick=()=>morse.reset();
$('morseSend').onclick=()=>morse.send();

$('sbSave').onclick=()=>{
  const url=$('sbUrl').value.trim(), key=$('sbKey').value.trim();
  if(!url||!key){ log('Укажи URL и anon key Supabase.'); return; }
  localStorage.setItem('kw66msg_sb_url',url);
  localStorage.setItem('kw66msg_sb_key',key);
  relay.init(url,key);
  log('Supabase настроен.');
};
$('createInvite').onclick=async()=>{
  if(!relay.configured()){ log('Сначала сохрани настройки Supabase.'); return; }
  try{
    const code=await relay.createInvite();
    $('inviteOut').innerHTML=`Код приглашения: <code>${code}</code> — передай его второму устройству и жди подключения…`;
    log(`Приглашение создано: ${code}. Ожидаю второе устройство…`);
    const peerPubB64=await relay.waitForPeerPub(code);
    await identity.setPeerFromB64(peerPubB64);
    await establishPairing(code);
    await relay.cleanupPairRow(code);
  }catch(e){ log(`Ошибка pairing: ${e.message}`); }
};
$('joinInvite').onclick=async()=>{
  if(!relay.configured()){ log('Сначала сохрани настройки Supabase.'); return; }
  const code=$('inviteInput').value.trim().toUpperCase();
  if(!code){ log('Введи код приглашения.'); return; }
  try{
    await relay.joinWithCode(code);
    await establishPairing(code);
    await relay.cleanupPairRow(code);
  }catch(e){ log(`Ошибка pairing: ${e.message}`); }
};
$('forgetPair').onclick=async()=>{
  if(!confirm('Точно забыть эту пару? Придётся пройти pairing заново на обоих устройствах.')) return;
  await identity.forgetAll();
};

/* ---------- восстановление состояния при перезапуске ---------- */
(async function init(){
  const url=localStorage.getItem('kw66msg_sb_url'), key=localStorage.getItem('kw66msg_sb_key');
  if(url&&key){ $('sbUrl').value=url; $('sbKey').value=key; relay.init(url,key); }
  const restored=await identity.restore();
  if(restored && restored.paired && relay.configured()){
    relay.pairId=restored.pairId; relay.role=restored.role;
    relay.subscribeMessages(onIncomingMessage);
    setPairUi(true);
    log(`Пара восстановлена (${restored.role==='a'?'A':'B'}), канал ${restored.pairId}.`);
  }
  setBleUi(false);
  if('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(()=>{});
  log(`Web Bluetooth: ${navigator.bluetooth?'доступен':'недоступен'}.`);
})();
