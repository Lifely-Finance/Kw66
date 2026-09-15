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
let device=null, server=null, txChars=[], activeTx=null, cameraTx=null, rxBuffers={};
let cameraWanted=false;

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
      log("GATT отключён.");
      server=null; txChars=[]; activeTx=null; cameraTx=null; rxBuffers={};
      setBleUi(false);
    }, {once:true});
    server=await device.gatt.connect();
    log(`GATT подключён: ${device.name||"(без имени)"}`);
    const services=await server.getPrimaryServices();
    const chars=[];
    for(const s of services){ for(const c of await s.getCharacteristics()) chars.push(c); }
    txChars=chars.filter(c=>[UUID.tx4,UUID.tx5,UUID.txAlt].some(u=>u===c.uuid.toLowerCase()) && (c.properties?.write||c.properties?.writeWithoutResponse));
    const rxChars=chars.filter(c=>[UUID.rx4,UUID.rx5,UUID.rxAlt].some(u=>u===c.uuid.toLowerCase()) && (c.properties?.notify||c.properties?.indicate));
    cameraTx=chars.find(c=>c.uuid.toLowerCase()===UUID.tx4 && (c.properties?.write||c.properties?.writeWithoutResponse))||null;
    activeTx=cameraTx||txChars[0]||null;
    for(const c of rxChars){
      await c.startNotifications();
      c.addEventListener("characteristicvaluechanged",e=>{
        const v=e.target.value;
        pushToBuffer(new Uint8Array(v.buffer.slice(v.byteOffset,v.byteOffset+v.byteLength)));
      });
    }
    setBleUi(!!activeTx);
    log(`Готово. TX=${txChars.length}, RX=${rxChars.length}.`);
    if(cameraWanted && cameraTx){
      // После нового GATT-сеанса состояние camera/shake-mode на часах могло сброситься.
      // Переармируем именно после подписки на notifications.
      await sleep(250);
      await sendCameraMode(true, {rearm:true, quiet:true});
    }
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
  enabled:false, includeTelemetry:false, lastT:{}, startT:null,
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


/* ============================================================
   Event Monitor + programmable watch patterns
   Все входящие BLE-пакеты проходят через нормализатор событий.
   Паттерны сохраняются локально и могут запускать действия.
   ============================================================ */
const WATCH_EVENT = {
  'D1:09':'DOT', 'D1:08':'DASH', 'D1:07':'PLAY',
  'D1:11':'CAMERA_OPEN', 'D1:0F':'CAMERA_CLOSE',
  'C4:01':'CAMERA_MODE_ON', 'C4:02':'CAMERA_SHUTTER', 'C4:03':'CAMERA_MODE_OFF'
};
function packetKey(bytes){
  return bytes.length>=2 ? `${bytes[0].toString(16).padStart(2,'0').toUpperCase()}:${bytes[1].toString(16).padStart(2,'0').toUpperCase()}` : null;
}
function isTelemetry(bytes){ return bytes.length>=2 && bytes[0]===0xA2; }
const patternEngine = {
  patterns: JSON.parse(localStorage.getItem('kw66_patterns')||'[]'),
  capture:false, captureName:'', captureSeq:[], captureLast:0,
  activeSeq:[], lastEventT:0, gapMs:1400,
  save(){ localStorage.setItem('kw66_patterns',JSON.stringify(this.patterns)); this.render(); },
  normalize(bytes){
    if(!bytes?.length || isTelemetry(bytes)) return null;
    const key=packetKey(bytes);
    return key ? (WATCH_EVENT[key]||key) : `OP_${bytes[0].toString(16).padStart(2,'0').toUpperCase()}`;
  },
  event(bytes){
    const name=this.normalize(bytes); if(!name) return;
    const t=performance.now();
    const dt=this.lastEventT?Math.round(t-this.lastEventT):null;
    this.lastEventT=t;
    const el=$('eventLog');
    if(el){
      const key=hex(bytes);
      const label=WATCH_EVENT[packetKey(bytes)]||'UNKNOWN';
      const line=`${new Date().toLocaleTimeString()}  ${key}  → ${label}${dt!==null?`  Δ${dt}ms`:''}`;
      el.textContent+=(el.textContent?'\n':'')+line; el.scrollTop=el.scrollHeight;
    }
    if(this.capture){
      if(this.captureLast && t-this.captureLast>this.gapMs) this.captureSeq=[];
      this.captureSeq.push(name); this.captureLast=t; this.renderCapture();
      return;
    }
    if(this.activeSeq.length && dt!==null && dt>this.gapMs) this.activeSeq=[];
    this.activeSeq.push(name);
    if(this.activeSeq.length>12) this.activeSeq.shift();
    this.match();
    this.renderLive();
  },
  match(){
    for(const p of this.patterns){
      if(!p.enabled) continue;
      if(this.activeSeq.length>=p.seq.length){
        const tail=this.activeSeq.slice(-p.seq.length);
        if(tail.every((x,i)=>x===p.seq[i])){ this.runAction(p.action,p.name); this.activeSeq=[]; return; }
      }
    }
  },
  runAction(action,name){
    log(`Паттерн «${name}» сработал → ${action}`);
    if(action==='LOCK_PHONE'){
      log('LOCK_PHONE: PWA не может напрямую заблокировать Android. Нужен Android companion с DevicePolicyManager/Device Admin.'); return;
    }
    if(action==='CAMERA_PROBE'){ sendCameraMode(true).catch(e=>log(`Camera probe: ${e.message}`)); return; }
    if(action==='CLEAR_MORSE'){ morse.reset(); return; }
    if(action==='PLAY_NEXT'){ bleSend(Uint8Array.from([0xD1,0x08])).catch(e=>log(`Действие: ${e.message}`)); return; }
  },
  startCapture(){ this.capture=true; this.captureSeq=[]; this.captureLast=0; this.renderCapture(); log('Запись паттерна: выполняй последовательность кнопок/жестов на часах.'); },
  stopCapture(){ this.capture=false; this.renderCapture(); return this.captureSeq.slice(); },
  renderCapture(){ const el=$('patternCapture'); if(el) el.textContent=this.captureSeq.length?this.captureSeq.join(' → '):'—'; },
  renderLive(){ const el=$('patternLive'); if(el) el.textContent=this.activeSeq.join(' → ')||'—'; },
  render(){
    const el=$('patternList'); if(!el) return; el.innerHTML='';
    if(!this.patterns.length){ el.innerHTML='<div class="muted">Паттернов пока нет.</div>'; return; }
    this.patterns.forEach((p,i)=>{
      const row=document.createElement('div'); row.className='patternRow';
      row.innerHTML=`<div style="flex:1"><b>${escapeHtml(p.name)}</b><div class="muted">${escapeHtml(p.seq.join(' → '))}</div></div><select data-i="${i}" class="patternAction">
        <option value="LOCK_PHONE"${p.action==='LOCK_PHONE'?' selected':''}>Заблокировать телефон*</option>
        <option value="CAMERA_PROBE"${p.action==='CAMERA_PROBE'?' selected':''}>Режим камеры</option>
        <option value="CLEAR_MORSE"${p.action==='CLEAR_MORSE'?' selected':''}>Сбросить Морзе</option>
        <option value="PLAY_NEXT"${p.action==='PLAY_NEXT'?' selected':''}>Тест: Next</option>
      </select><button data-del="${i}" class="danger">×</button>`;
      el.appendChild(row);
    });
    el.querySelectorAll('.patternAction').forEach(s=>s.onchange=()=>{this.patterns[+s.dataset.i].action=s.value;this.save();});
    el.querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>{this.patterns.splice(+b.dataset.del,1);this.save();});
  }
};
function escapeHtml(s){ return String(s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
async function sendCameraMode(on,{rearm=false,quiet=false}={}){
  if(!cameraTx) throw new Error('Камера: TX 000033F1 недоступен — сначала подключи часы');
  if(on){
    // C4 03 → пауза → C4 01. Это сбрасывает старое состояние режима после reconnect.
    if(rearm || cameraWanted || on){
      await writeCamera([0xC4,0x03]);
      await sleep(180);
    }
    await writeCamera([0xC4,0x01]);
    cameraWanted=true;
    if(!quiet) log(rearm?'TX → C4 03 → C4 01 (camera mode re-arm)':'TX → C4 01 (camera mode)');
  }else{
    await writeCamera([0xC4,0x03]);
    cameraWanted=false;
    if(!quiet) log('TX → C4 03 (camera mode off)');
  }
}
async function writeCamera(bytes){
  const u8=Uint8Array.from(bytes);
  if(cameraTx.properties.writeWithoutResponse && !cameraTx.properties.write) await cameraTx.writeValueWithoutResponse(u8);
  else await cameraTx.writeValue(u8);
}

/* ---------- сборка фрагментов D1/C5 (упрощено под нужды мессенджера) ---------- */
function pushToBuffer(bytes){
  if(bytes.length===0) return;
  if(rawRec.enabled && (!isTelemetry(bytes) || rawRec.includeTelemetry)) rawRec.log(bytes);
  patternEngine.event(bytes);
  const op=bytes[0];
  if(op===0xD1 && bytes.length>=2){ handleD1(bytes); return; }
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
   Морзе-ввод — раскладка «телеграфный ключ»: точка и тире — это
   отдельные кнопки (крайние), Play — единственная управляющая
   кнопка, смысл которой определяется числом тапов подряд.

   Previous:   1 тап = точка (немедленно, без задержки/окна)
   Next:       1 тап = тире  (немедленно, без задержки/окна)
   Play:       1 тап              = зафиксировать букву / пробел
               2 тапа подряд      = отправить сообщение
               3 тапа подряд      = удалить (незавершённую букву
                                     целиком, а если её нет — последнюю
                                     зафиксированную)

   Previous/Next независимы друг от друга и не привязаны к
   предыдущему тапу — калибровка темпа не нужна, буквы, начинающиеся с тире
   (T, N, M, O, ...), вводятся с первого раза.

   Время используется только для границ:
   - короткая пауза: продолжаем текущую букву;
   - MORSE_LETTER_GAP_MS: фиксируем букву;
   - MORSE_WORD_GAP_MS: фиксируем букву и автоматически ставим пробел.

   Play остаётся ручным управлением:
   1 тап = буква / пробел, 2 = отправка, 3+ = удаление.
   Для Previous/Next намеренно НЕ используется debounce/dedup в этой версии:
   каждое пришедшее D1 09/D1 08 считается отдельным касанием.
   ============================================================ */
const MORSE_EN={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'};
const MORSE_RU={'.-':'А','-...':'Б','.--':'В','--.':'Г','-..':'Д','.':'Е','...-':'Ж','--..':'З','..':'И','.---':'Й','-.-':'К','.-..':'Л','--':'М','-.':'Н','---':'О','.--.':'П','.-.':'Р','...':'С','-':'Т','..-':'У','..-.':'Ф','....':'Х','---.':'Ц','----':'Ч','--.-':'Ш','--.--':'Щ','-.--':'Ы','-..-':'Ь','..-..':'Э','..--':'Ю','.-.-':'Я'};
const MORSE_MAP={...MORSE_EN,...MORSE_RU};

// Если паттерн не распознан — ищем ближайший валидный код Морзе на
// расстоянии 1 элемент (одна замена точка<->тире, лишний или
// пропущенный элемент). Это чинит типичные единичные ошибки набора
// ДО словарной коррекции, без всякого UI — просто выбирается самый
// вероятный код из уже подтверждённого алфавита.
function nearestMorsePattern(pattern){
  const candidates=[];
  // замена одного элемента
  for(let i=0;i<pattern.length;i++){
    const flipped=pattern.slice(0,i)+(pattern[i]==='.'?'-':'.')+pattern.slice(i+1);
    if(MORSE_MAP[flipped]) candidates.push(flipped);
  }
  // лишний элемент (удаляем один)
  for(let i=0;i<pattern.length;i++){
    const shorter=pattern.slice(0,i)+pattern.slice(i+1);
    if(MORSE_MAP[shorter]) candidates.push(shorter);
  }
  // пропущенный элемент (добавляем точку или тире в каждую позицию)
  for(let i=0;i<=pattern.length;i++){
    for(const sym of ['.','-']){
      const longer=pattern.slice(0,i)+sym+pattern.slice(i);
      if(MORSE_MAP[longer]) candidates.push(longer);
    }
  }
  if(!candidates.length) return null;
  candidates.sort((a,b)=>Math.abs(a.length-pattern.length)-Math.abs(b.length-pattern.length)); // сперва замена (та же длина), затем удаление/добавление
  return candidates[0];
}
const BURST_WINDOW_MS=450; // окно серии тапов Play: 1=буква/пробел, 2=отправить, 3=удалить
const MORSE_LETTER_GAP_MS=900;  // после последнего элемента: завершить букву
const MORSE_WORD_GAP_MS=1800;   // после последнего элемента: завершить букву + пробел

function burstTracker(onFinalize,windowMs=BURST_WINDOW_MS){
  const s={count:0,timer:null};
  return ()=>{
    s.count++;
    clearTimeout(s.timer);
    s.timer=setTimeout(()=>{ const c=s.count; s.count=0; onFinalize(c); },windowMs);
  };
}

const morse={
  pattern:'', text:'', symbols:0, letters:0, debug:false,
  boundaryTimer:null, wordTimer:null,
  setState(s){ $('morseState').textContent=s; },
  ui(){ $('morseSymbols').textContent=this.symbols; $('morseLetters').textContent=this.letters; },
  dbg(s){ if(this.debug){ const el=$('morseDebugOut'); el.style.display='block'; el.textContent+=(el.textContent?'\n':'')+`[${nowStr()}] ${s}`; el.scrollTop=el.scrollHeight; } },
  clearBoundaryTimers(){
    clearTimeout(this.boundaryTimer);
    clearTimeout(this.wordTimer);
    this.boundaryTimer=null;
    this.wordTimer=null;
  },
  scheduleBoundaries(){
    this.clearBoundaryTimers();
    this.boundaryTimer=setTimeout(()=>{
      this.boundaryTimer=null;
      if(this.pattern){
        this.commitLetter(false);
        this.setState('буква принята (пауза)');
      }
    },MORSE_LETTER_GAP_MS);
    this.wordTimer=setTimeout(()=>{
      this.wordTimer=null;
      if(this.pattern) this.commitLetter(false);
      if(this.text && !this.text.endsWith(' ')){
        this.text+=' ';
        this.symbols++;
        this.setState('пробел (пауза)');
        this.ui();
        this.dbg('автоматический пробел по длинной паузе');
      }
    },MORSE_WORD_GAP_MS);
  },
  addElement(sym){
    this.pattern+=sym; this.symbols++;
    $('morseLast').textContent=sym==='.'?'·':'−';
    this.setState('приём'); this.ui();
    this.dbg(`элемент ${sym} pattern=${this.pattern}`);
    this.scheduleBoundaries();
  },
  commitLetter(manual=true){
    if(!this.pattern) return false;
    if(manual) this.clearBoundaryTimers();
    let ch=MORSE_MAP[this.pattern];
    if(!ch){
      const fixed=nearestMorsePattern(this.pattern);
      if(fixed){ ch=MORSE_MAP[fixed]; this.dbg(`паттерн ${this.pattern} не распознан → исправлен на ${fixed} = ${ch}`); }
      else ch='□';
    }
    this.text+=ch; this.letters++;
    this.dbg(`буква=${ch} (${this.pattern})`);
    this.pattern='';
    $('morseLast').textContent=ch; this.setState('буква принята'); this.ui();
    return true;
  },
  addSpace(){
    this.clearBoundaryTimers();
    this.commitLetter();
    if(this.text && !this.text.endsWith(' ')){ this.text+=' '; this.letters++; this.symbols++; }
    $('morseLast').textContent='Пробел'; this.setState('пробел'); this.ui(); this.dbg('пробел');
  },
  deleteLast(){
    this.clearBoundaryTimers();
    if(this.pattern){ this.pattern=''; this.setState('удаление'); $('morseLast').textContent='⌫ буква (незаверш.)'; this.ui(); return; }
    if(this.text){
      const chars=[...this.text];
      const removed=chars.pop();
      this.text=chars.join('');
      if(removed===' ') this.symbols=Math.max(0,this.symbols-1);
      else this.letters=Math.max(0,this.letters-1);
    }
    this.setState('удаление'); $('morseLast').textContent='⌫ буква'; this.ui();
  },
  reset(){
    this.clearBoundaryTimers();
    if(this.pendingTimer) clearTimeout(this.pendingTimer);
    this.pendingTimer=null; this.pendingSend=null;
    this.pattern='';this.text='';this.symbols=0;this.letters=0;
    this.setState('ожидание');$('morseLast').textContent='—';this.ui();$('morseDebugOut').textContent='';this.dbg('reset');
  },
  // ВРЕМЕННО (только для тестов): отправить набранный текст прямо на
  // те же часы через sendWatchText, минуя шифрование и relay —
  // имитация "входящего" сообщения без второго телефона/часов.
  // Убрать перед реальным использованием на два устройства.
  async simulateReceive(){
    this.commitLetter();
    if(!this.text){ log('[ТЕСТ] Нет текста — сначала введи сообщение на часах.'); return; }
    const text=this.text;
    try{
      await sendWatchText(text);
      this.setState('тест: показано как входящее'); $('morseLast').textContent='тест-приём';
      log(`[ТЕСТ] Отправлено на часы как имитация входящего (${text.length} симв.), без шифрования и сети.`);
    }catch(e){
      log(`[ТЕСТ] Ошибка: ${e.message}`);
    }finally{
      this.text=''; this.pattern=''; this.letters=0; this.symbols=0; this.ui();
      setTimeout(()=>this.setState('ожидание'),900);
    }
  },
  pendingSend:null, pendingTimer:null,
  // Play x2 запускает это вместо немедленной отправки: считаем
  // словарную коррекцию, показываем результат на СВОИХ же часах
  // (используя тот же sendWatchText, что и для входящих) и ждём
  // окно PREVIEW_WINDOW_MS. Любой тап в это окно — отмена (см.
  // cancelPendingSend/handleD1), молчание — подтверждение.
  async requestSend(){
    this.commitLetter();
    if(!this.text) return;
    if(!identity.sessionKey){ log('Отправка невозможна: пара не установлена (см. раздел 2).'); return; }
    const raw=this.text;
    const corrected=(window.KW66Dict?window.KW66Dict.correctMessage(raw):raw);
    this.pendingSend={raw,corrected};
    const windowMs=Math.min(6000,Math.max(2500,corrected.length*180));
    try{
      await sendWatchText(corrected);
      this.dbg(`превью показано (${corrected.length} симв.), окно ${windowMs}мс; исходник не изменён до подтверждения`);
    }catch(e){
      log(`Ошибка предпросмотра: ${e.message}`);
    }
    this.setState('превью — жди или отмени тапом'); $('morseLast').textContent='превью';
    this.pendingTimer=setTimeout(()=>this.confirmSend(),windowMs);
  },
  async confirmSend(){
    if(!this.pendingSend) return;
    const {corrected}=this.pendingSend;
    clearTimeout(this.pendingTimer); this.pendingTimer=null; this.pendingSend=null;
    try{
      const packet=await identity.encrypt(corrected);
      await relay.sendCiphertext(packet);
      this.setState('отправлено'); $('morseLast').textContent='отправлено';
      this.dbg(`отправлено, длина=${corrected.length} символов; открытый текст нигде не сохранён`);
    }catch(e){
      log(`Ошибка отправки: ${e.message}`);
    }finally{
      this.text=''; this.pattern=''; this.letters=0; this.symbols=0; this.ui();
      setTimeout(()=>this.setState('ожидание'),900);
    }
  },
  // Любой тап во время превью зовёт это: возвращаем ИСХОДНЫЙ
  // (нескорректированный) текст в буфер для ручной правки — если
  // словарь угадал неверно, автокоррекция не должна тебе мешать.
  cancelPendingSend(){
    if(!this.pendingSend) return false;
    clearTimeout(this.pendingTimer); this.pendingTimer=null;
    this.text=this.pendingSend.raw; this.pendingSend=null;
    this.setState('приём'); this.ui(); this.dbg('превью отменено, возвращён исходный текст');
    return true;
  }
};

function finalizePlay(count){
  if(count===1){
    if(morse.pattern) morse.commitLetter();      // есть незавершённая буква — фиксируем, переходим к следующей
    else morse.addSpace();                       // буквы уже нет — значит это пробел
  } else if(count===2){
    morse.requestSend().catch(e=>log(`Ошибка отправки: ${e.message}`));
  } else if(count>=3){
    morse.deleteLast();
  }
}
const trackPlay=burstTracker(finalizePlay);

function handleD1(b){
  if(!b || b[0]!==0xD1 || b.length<2) return false;
  const code=b[1];
  if(morse.pendingSend){ morse.cancelPendingSend(); return true; } // любой тап во время превью — отмена, действие нужно повторить
  if(code===0x09){ morse.addElement('.'); return true; }  // Previous: точка
  if(code===0x08){ morse.addElement('-'); return true; } // Next: тире
  if(code===0x07){ trackPlay(); return true; }                                         // Play: команда (1/2/3 тапа)
  return false;
}

/* ============================================================
   Привязка UI
   ============================================================ */
$('connect').onclick=connect;
$('disconnect').onclick=async()=>{ try{ if(device?.gatt?.connected) device.gatt.disconnect(); }catch{} };
$('clearLog').onclick=()=>{ $('log').textContent=''; };

$('rawRecToggle').onchange=e=>{ rawRec.enabled=e.target.checked; if(rawRec.enabled) rawRec.clear(); };
$('rawTelemetryToggle').onchange=e=>{ rawRec.includeTelemetry=e.target.checked; };
$('eventClear').onclick=()=>{ $('eventLog').textContent=''; patternEngine.activeSeq=[]; patternEngine.renderLive(); };
$('rawRecClear').onclick=()=>rawRec.clear();

$('morseDebug').onchange=e=>{ morse.debug=e.target.checked; $('morseDebugOut').style.display=morse.debug?'block':'none'; };
$('morseTestDot').onclick=()=>morse.addElement('.');
$('morseTestDash').onclick=()=>morse.addElement('-');
$('morseTestCommit').onclick=()=>morse.commitLetter();
$('morseSpace').onclick=()=>morse.addSpace();
$('morseReset').onclick=()=>morse.reset();
$('morseSend').onclick=()=>morse.requestSend();
$('morseSimulateReceive').onclick=()=>morse.simulateReceive();
$('eventClear').onclick=()=>{ const e=$('eventLog'); if(e)e.textContent=''; };
$('patternStart').onclick=()=>patternEngine.startCapture();
$('patternStop').onclick=()=>{
  const seq=patternEngine.stopCapture();
  if(!seq.length){ log('Паттерн пустой.'); return; }
  const name=prompt('Название паттерна:', 'Новый паттерн');
  if(!name) return;
  patternEngine.patterns.push({name,seq,action:'LOCK_PHONE',enabled:true});
  patternEngine.save();
  log(`Паттерн «${name}» сохранён: ${seq.join(' → ')}`);
};
$('cameraOn').onclick=()=>sendCameraMode(true).catch(e=>log(`C4 01: ${e.message}`));
$('cameraOff').onclick=()=>sendCameraMode(false).catch(e=>log(`C4 03: ${e.message}`));
patternEngine.render();

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
