/* ============================================================
   KW66 Lab v3.6
   GloryFit BLE: command lab + HR analytics + fuzzer + btsnoop
   v3.1: перенесены фиксы буферизации из отдельной ветки —
   F7=11 байт (min/max HR в хвосте), E5 не фиксированной длины
   (2 или 4 байта, resync+debounce вместо склейки с соседним
   пакетом), восстановлена ветка writeValueWithoutResponse,
   добавлено пассивное прослушивание FEE7.
   ============================================================ */
"use strict";

/* ---------- константы ---------- */
const UUID = {
  service4: "000055ff-0000-1000-8000-00805f9b34fb",
  service5: "000056ff-0000-1000-8000-00805f9b34fb",
  tx4: "000033f1-0000-1000-8000-00805f9b34fb",
  rx4: "000033f2-0000-1000-8000-00805f9b34fb",
  tx5: "000034f1-0000-1000-8000-00805f9b34fb",
  rx5: "000034f2-0000-1000-8000-00805f9b34fb",
  txAlt: "0000b003-0000-1000-8000-00805f9b34fb",
  rxAlt: "0000b004-0000-1000-8000-00805f9b34fb",
  battery: "00002a19-0000-1000-8000-00805f9b34fb",
  fee7Notify: "0000fea1-0000-1000-8000-00805f9b34fb",
  fee7Indicate: "0000fea2-0000-1000-8000-00805f9b34fb"
};
const LABELS = {
  [UUID.rx4]: "BLE4", [UUID.tx4]: "BLE4",
  [UUID.rx5]: "BLE5", [UUID.tx5]: "BLE5",
  [UUID.rxAlt]: "ALT", [UUID.txAlt]: "ALT",
  [UUID.battery]: "BAT",
  [UUID.fee7Notify]: "FEE7", [UUID.fee7Indicate]: "FEE7"
};
// ожидаемые длины пакетов по opcode. E5 сюда намеренно НЕ включён: на
// практике он бывает и 2 байта ("E5 11" — отметка "идёт измерение" без
// значения), и 4 байта ("E5 11 00 XX" с реальным пульсом) — фиксированная
// длина склеивала короткий вариант со следующим случайным пакетом.
// F7 — 11 байт (не 9): последние 2 байта — min/max пульса, подтверждено
// живым значением характеристики в nRF Connect.
const KNOWN_LEN = { 0xA2: 2, 0xA3: 8, 0xF7: 11 };
// периодический «фон» — для фаззера и статистики не считается ответом
const PERIODIC_OPS = new Set([0xA2, 0xF7, 0xB1]);
const UNKNOWN_TRACK_OPS = new Set([0xCB, 0x31]);
const GF_KEYS = ["55ff","56ff","33f1","33f2","34f1","34f2","b003","b004","2a19"];

/* ---------- состояние ---------- */
let device=null, server=null, txChars=[], rxCharsAll=[], batteryChar=null, activeTx=null;
let logRows=[], rxCount=0, hrCount=0, rxBuffers={};
let hrHistory=[];            // {t, hr}
let lastSteps=null, lastStepsT=0;
let rxFeed=[];               // {t, hex, op} — последние RX для фаззера
let currentHR=null;

/* ---------- утилиты ---------- */
const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));
function now(){ return new Date().toLocaleTimeString(); }
function hex(bytes){
  return [...bytes].map(x=>x.toString(16).padStart(2,"0").toUpperCase()).join(" ");
}
function hexToBytes(s){
  const clean=s.replace(/0x/gi,"").replace(/[^0-9a-f]/gi,"");
  if(clean.length===0 || clean.length%2) throw new Error("Некорректный HEX");
  const out=new Uint8Array(clean.length/2);
  for(let i=0;i<out.length;i++) out[i]=parseInt(clean.slice(i*2,i*2+2),16);
  return out;
}
function labelFor(uuid){ return LABELS[uuid?.toLowerCase()] || uuid; }
function looksLike(uuid, target){ return uuid.toLowerCase()===target.toLowerCase(); }
function log(s){
  const line=`[${now()}] ${s}`;
  $("log").textContent += ($("log").textContent ? "\n" : "") + line;
  $("log").scrollTop=$("log").scrollHeight;
}
function record(direction, bytes, uuid){
  const value=hex(bytes);
  logRows.push({time:new Date().toISOString(), direction, hex:value, source:uuid?labelFor(uuid):undefined});
  if(direction==="RX"){
    rxCount++; $("rxCount") && ($("rxCount").textContent=rxCount);
    if(window.protocolLab) protocolLab.recordMotion(bytes, uuid);
    if($("protoRxCount")) $("protoRxCount").textContent=rxCount;
  }
}
function setConnected(v){
  ["battery","steps","sendCustom","sendWatchText"].forEach(id=>$(id).disabled=!v);
  $("hrReq").disabled=!v;
  $("recStart").disabled=!v;
  $("stressToggle").disabled=!v;
}

/* ---------- подключение ---------- */
function characteristicProps(c){
  const p=c.properties||{}, out=[];
  if(p.read) out.push("read");
  if(p.write) out.push("write");
  if(p.writeWithoutResponse) out.push("writeWithoutResponse");
  if(p.notify) out.push("notify");
  if(p.indicate) out.push("indicate");
  return out.join(", ")||"—";
}
function renderTxSelect(){
  const sel=$("txSelect"); sel.innerHTML="";
  txChars.forEach((c,i)=>{
    const o=document.createElement("option");
    o.value=i; o.textContent=`${labelFor(c.uuid)} ${c.uuid.slice(0,8)}… [${characteristicProps(c)}]`;
    if(c===activeTx) o.selected=true;
    sel.appendChild(o);
  });
  sel.onchange=()=>{ activeTx=txChars[+sel.value]; log(`TX канал: ${labelFor(activeTx.uuid)}`); };
}
async function subscribe(c){
  await c.startNotifications();
  c.addEventListener("characteristicvaluechanged", e=>{
    const v=e.target.value;
    pushToBuffer(c.uuid, new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset+v.byteLength)));
  });
}
async function connect(){
  if(!navigator.bluetooth){ log("Web Bluetooth недоступен. Нужен Chrome/Android или Bluefy на iOS."); return; }
  try{
    log("Поиск устройства…");
    device=await navigator.bluetooth.requestDevice({
      acceptAllDevices:true,
      optionalServices:[UUID.service4, UUID.service5, UUID.battery]
    });
    device.addEventListener("gattserverdisconnected",()=>{
      log("GATT disconnected.");
      server=null; txChars=[]; rxCharsAll=[]; activeTx=null; batteryChar=null; rxBuffers={};
      setConnected(false);
      $("device").textContent="Отключено";
    });
    server=await device.gatt.connect();
    log(`GATT connected: ${device.name||"(без имени)"}`);
    $("device").textContent=`Выбрано: ${device.name||"(без имени)"} (${device.id})`;
    const services=await server.getPrimaryServices();
    const chars=[];
    for(const s of services){
      log(`SERVICE ${s.uuid}`);
      for(const c of await s.getCharacteristics()){ chars.push(c); log(`CHAR ${c.uuid} [${characteristicProps(c)}]`); }
    }
    const txCand=chars.filter(c=>[UUID.tx4,UUID.tx5,UUID.txAlt].some(u=>looksLike(c.uuid,u)));
    const rxCand=chars.filter(c=>[UUID.rx4,UUID.rx5,UUID.rxAlt].some(u=>looksLike(c.uuid,u)));
    txChars=txCand.filter(c=>c.properties?.write||c.properties?.writeWithoutResponse);
    rxCharsAll=rxCand.filter(c=>c.properties?.notify||c.properties?.indicate);
    batteryChar=chars.find(c=>looksLike(c.uuid,UUID.battery));
    activeTx=txChars[0]||null;
    $("txChar").textContent=txChars.map(c=>labelFor(c.uuid)).join(", ")||"не найден";
    $("rxChar").textContent=rxCharsAll.map(c=>labelFor(c.uuid)).join(", ")||"не найден";
    renderTxSelect();
    for(const c of rxCharsAll) await subscribe(c);
    if(batteryChar?.properties?.notify && !rxCharsAll.length) await subscribe(batteryChar);
    // Пассивно слушаем малоизученный канал FEE7 (Tencent/WeRun UUID) —
    // вдруг оттуда сама пойдёт какая-то полезная телеметрия.
    const fee7Chars=chars.filter(c=>looksLike(c.uuid,UUID.fee7Notify)||looksLike(c.uuid,UUID.fee7Indicate));
    for(const c of fee7Chars){ if(c.properties.notify||c.properties.indicate) await subscribe(c); }
    setConnected(txChars.length>0);
    log(`Профиль GloryFit: TX=${txChars.length}, RX=${rxCharsAll.length}`);
    updateProtocolUi();
  }catch(e){
    log(`ОШИБКА: ${e.name||"Error"}: ${e.message||e}`);
  }
}
async function send(bytes){
  if(!activeTx) throw new Error("Нет TX-канала");
  const u8=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
  if(activeTx.properties.writeWithoutResponse && !activeTx.properties.write){
    await activeTx.writeValueWithoutResponse(u8);
  } else {
    await activeTx.writeValue(u8);
  }
  record("TX", u8, activeTx.uuid);
  log(`TX → ${hex(u8)}`);
}
async function readBattery(){
  try{
    if(batteryChar?.properties?.read){
      const v=await batteryChar.readValue();
      const b=new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset+v.byteLength));
      record("RX", b, batteryChar.uuid);
      if(b.length>=2 && b[0]===0xA2){ $("batVal").textContent=b[1]; log(`Батарея: ${b[1]}%`); }
    }else await send([0xA2]);
  }catch(e){ log(`Battery ERROR: ${e.message}`); }
}

/* ---------- 0xC5: произвольный текст на часы ----------
   Уточнено по обратной связи с реального железа + повторной сверке с
   btsnoop: у сообщения есть служебный заголовок, который в v3.2 был по
   ошибке пропущен (первый байт "съедался" как часть текста, отсюда баг
   "текст без первого символа").
     TX (33F1), seq=0:  C5 00 <id:1б> <len:1б, байт текста всего> <текст…>
     TX (33F1), seq>0:  C5 <seq> <текст…, до 18 байт>
     TX (33F1), конец:  C5 FD
     RX (33F2): C5 <seq> — квитанция куска, C5 FD <статус> — приём завершён
   id — похоже на категорию уведомления, не мусор: в логе единственный
   пойманный случай id=0x00 — это уведомление о звонке (на часах это
   показывается как экран вызова с кнопкой сброса — ровно то, что ты
   словил через пробелы). Ненулевые id (в логе — 0x02/0x04/0x09/0x13/0x15)
   давали обычную иконку приложения. По умолчанию используем 0x01 —
   не проверено на других значениях, кроме факта "не 0". len — 1 байт,
   т.е. надёжно ловит текст максимум ~127 символов (255 байт UTF-16BE);
   длиннее — часы, вероятно, либо обрежут, либо не поймут заголовок. */
function utf16beBytes(str){
  const out=new Uint8Array(str.length*2);
  for(let i=0;i<str.length;i++){
    const cu=str.charCodeAt(i);
    out[i*2]=(cu>>8)&0xFF;
    out[i*2+1]=cu&0xFF;
  }
  return out;
}
async function sendWatchText(text, id=0x01){
  if(!text) return;
  const payload=utf16beBytes(text);
  if(payload.length>255){
    log(`Текст слишком длинный (${payload.length} байт UTF-16BE, лимит поля длины — 255): скорее всего часы отобразят его некорректно.`);
  }
  const totalLen=payload.length & 0xFF;
  const CHUNK=18;
  let seq=0, off=0;
  // первый кусок: 2 служебных байта (id, len) съедают часть бюджета в 18 байт
  const firstText=payload.slice(0, CHUNK-2);
  const p0=new Uint8Array(2+2+firstText.length);
  p0[0]=0xC5; p0[1]=seq; p0[2]=id&0xFF; p0[3]=totalLen;
  p0.set(firstText,4);
  await send(p0);
  seq=(seq+1)%0xFD; off=firstText.length;
  while(off<payload.length){
    const chunk=payload.slice(off, off+CHUNK);
    const p=new Uint8Array(2+chunk.length);
    p[0]=0xC5; p[1]=seq; p.set(chunk,2);
    await send(p);
    seq=(seq+1)%0xFD; off+=CHUNK;
    await sleep(40);
  }
  await send([0xC5,0xFD]);
  log(`Текст отправлен на часы: id=0x${(id&0xFF).toString(16).padStart(2,"0")}, ${payload.length} байт полезной нагрузки.`);
}

/* ---------- сборка фрагментов и декодинг ---------- */
function expectedLength(buf){
  const op=buf[0];
  if(op in KNOWN_LEN) return KNOWN_LEN[op];
  if(op===0xB1) return buf.length<2?null:18;        // realtime steps
  if(op===0xB2){
    if(buf.length<2) return null;
    if(buf[1]===0xFD) return 3;                      // терминатор истории (пусто): B2 FD E0/F5
    if(buf[1]===0x07) return 18;                     // запись истории
    return 2;                                        // короткие ack-подобные
  }
  return null;
}
const KNOWN_OPCODES = [0xA2, 0xA3, 0xB1, 0xB2, 0xE5, 0xF7];
function findNextKnownOpcodeIndex(buf){
  for(let i=1;i<buf.length;i++){
    if(KNOWN_OPCODES.includes(buf[i])) return i;
  }
  return -1;
}
let flushTimers={};
function pushToBuffer(uuid, bytes){
  const key=uuid||"unknown";
  const prev=rxBuffers[key]||new Uint8Array(0);
  const merged=new Uint8Array(prev.length+bytes.length);
  merged.set(prev,0); merged.set(bytes,prev.length);
  rxBuffers[key]=merged;
  flushBuffer(key, uuid);
  // страховка: короткий пакет вроде "E5 11" без продолжения не гадаем
  // сразу — ждём паузу, и если новых байт не пришло, разбираем как есть.
  if(flushTimers[key]) clearTimeout(flushTimers[key]);
  if(rxBuffers[key] && rxBuffers[key].length){
    flushTimers[key]=setTimeout(()=>{
      const pending=rxBuffers[key];
      if(pending && pending.length){ emitPacket(pending, uuid, true); rxBuffers[key]=new Uint8Array(0); }
    }, 25);
  }
}
function flushBuffer(key, uuid){
  let buf=rxBuffers[key];
  while(buf && buf.length){
    const need=expectedLength(buf);
    if(need===null){
      // неизвестный/переменной длины opcode: ищем начало следующего
      // известного пакета и сразу отрезаем "хвост" перед ним, не дожидаясь
      // искусственного порога — реальную длину досдаст debounce выше.
      const nextIdx=findNextKnownOpcodeIndex(buf);
      if(nextIdx>0){ emitPacket(buf.slice(0,nextIdx), uuid, true); buf=buf.slice(nextIdx); continue; }
      break;
    }
    if(buf.length<need) break;
    emitPacket(buf.slice(0,need), uuid, false);
    buf=buf.slice(need);
  }
  rxBuffers[key]=buf;
}
function emitPacket(bytes, uuid, isUnknown){
  record("RX", bytes, uuid);
  rxFeed.push({t:Date.now(), hex:hex(bytes), op:bytes[0]});
  if(rxFeed.length>800) rxFeed.splice(0, rxFeed.length-800);
  decodePacket(bytes, uuid);
}
function decodePacket(b, uuid){
  const label=uuid?labelFor(uuid):null;
  if(label && label!=="BLE4" && label!=="BLE5"){
    log(`  ↳ [${label}] сырые данные: ${hex(b)}`);
    return;
  }
  const src=uuid?`[${label}] `:"";
  const op=b[0];
  if(op===0xA2 && b.length>=2){
    $("batVal").textContent=b[1];
    log(`  ↳ ${src}A2: батарея = ${b[1]}%`);
  }
  else if(op===0xF7 && b.length===11){
    const yr=(b[2]<<8)|b[3];
    log(`  ↳ ${src}F7: время часов ≈ ${yr}-${b[4]}-${b[5]} ${b[6]}:${b[7]}, HR min/max=${b[9]}/${b[10]}`);
  }
  else if(op===0xE5 && b.length===4){
    const mode=b[1], hr=b[3];
    if(hr>=40 && hr<=200) onHR(hr, mode);
    else log(`  ↳ ${src}E5 mode=0x${mode.toString(16)}: bpm=${hr} вне диапазона`);
  }
  else if(op===0xE5 && b.length===2){
    log(`  ↳ ${src}E5: отметка "режим 0x${b[1].toString(16)}" без значения (сенсор ещё греется)`);
  }
  else if(op===0xB1 && b.length===18){
    // раскладка предположительная: последние 2 байта BE = шаги
    const steps=(b[16]<<8)|b[17];
    lastSteps=steps; lastStepsT=Date.now();
    $("stepsVal").textContent=steps;
    log(`  ↳ ${src}B1: шаги ≈ ${steps} (raw ${hex(b)})`);
  }
  else if(op===0xB2 && b.length>=2 && b[1]===0xFD){
    log(`  ↳ ${src}B2 FD ${b[2].toString(16)}: история пуста / конец передачи`);
  }
  else if(op===0xC5 && b.length>=2 && b[1]===0xFD){
    log(`  ↳ ${src}C5 FD: часы подтвердили приём текста (статус ${hex(b.slice(2))||"—"})`);
  }
  else if(op===0xC5 && b.length===2){
    log(`  ↳ ${src}C5: часы квитировали кусок #${b[1]}`);
  }
  else if(op===0xCB){
    log(`  ↳ ${src}CB: неизвестный RX-пакет (${hex(b)}) — не отправлять`);
  }
  else if(op===0x31){
    log(`  ↳ ${src}31: неизвестный RX-пакет (${hex(b)}) — не отправлять`);
  }
}

/* ---------- живой пульс ---------- */
function onHR(hr, mode){
  const t=Date.now();
  currentHR=hr;
  hrHistory.push({t, hr});
  const cutoff=t-10*60*1000;
  while(hrHistory.length && hrHistory[0].t<cutoff) hrHistory.shift();
  hrCount++;
  $("hrNow").textContent=hr+" bpm";
  $("hrCount").textContent=hrCount;
  const win=hrHistory.filter(s=>s.t>t-5*60*1000);
  const mn=Math.min(...win.map(s=>s.hr)), mx=Math.max(...win.map(s=>s.hr));
  const avg=Math.round(win.reduce((a,s)=>a+s.hr,0)/win.length);
  $("hrMinMax").textContent=`${mn} / ${mx}`;
  $("hrAvg").textContent=avg+" bpm";
  const pill=$("hrPill");
  pill.textContent="поток активен";
  pill.className="pill run";
  drawChart();
  recovery.onHR(hr, t);
  lie.onHR(hr, t);
}

let pillTimer=setInterval(()=>{
  if(currentHR && Date.now()-hrHistory[hrHistory.length-1]?.t>5000){
    const pill=$("hrPill"); pill.textContent="поток пропал"; pill.className="pill hot";
  }
},2000);

function drawChart(){
  const c=$("hrChart"); if(!c) return;
  const dpr=window.devicePixelRatio||1;
  const w=c.clientWidth, h=c.clientHeight;
  if(!w||!h) return;
  if(c.width!==Math.round(w*dpr)){ c.width=Math.round(w*dpr); c.height=Math.round(h*dpr); }
  const ctx=c.getContext("2d");
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,w,h);
  const SPAN=5*60*1000, tEnd=Date.now(), tStart=tEnd-SPAN;
  let vals=hrHistory.filter(s=>s.t>=tStart);
  if(vals.length<2){
    ctx.fillStyle="#9ca3af"; ctx.font="13px system-ui";
    ctx.fillText("Нет данных — запусти замер пульса на часах", 12, h/2);
    return;
  }
  let mn=Math.min(...vals.map(s=>s.hr)), mx=Math.max(...vals.map(s=>s.hr));
  mn=Math.max(40, mn-10); mx=Math.min(180, mx+10);
  const yOf=hr=>h-((hr-mn)/(mx-mn))*(h-24)-12;
  const xOf=t=>((t-tStart)/SPAN)*w;
  ctx.strokeStyle="#1e2a44"; ctx.fillStyle="#4b5878"; ctx.font="10px ui-monospace";
  for(let g=Math.ceil(mn/10)*10; g<=mx; g+=10){
    const y=yOf(g);
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke();
    ctx.fillText(g+"", 4, y-2);
  }
  ctx.strokeStyle="#60a5fa"; ctx.lineWidth=2; ctx.beginPath();
  vals.forEach((s,i)=>{ const x=xOf(s.t), y=yOf(s.hr); i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
  ctx.stroke();
  const last=vals[vals.length-1];
  ctx.fillStyle="#6ee7b7"; ctx.beginPath();
  ctx.arc(xOf(last.t), yOf(last.hr), 4, 0, Math.PI*2); ctx.fill();
  ctx.fillStyle="#eef2ff"; ctx.font="bold 12px system-ui";
  ctx.fillText(last.hr+" bpm", Math.min(xOf(last.t)+8, w-60), yOf(last.hr)+4);
}
window.addEventListener("resize", drawChart);

/* ---------- тест восстановления (перетрен) ---------- */
const recovery={
  state:"idle", t0:0, firstHr:null, endHr:null, timer:null,
  start(){
    if(this.state==="run") return;
    this.state="run"; this.t0=Date.now(); this.firstHr=null; this.endHr=null;
    $("recPill").textContent="идёт тест"; $("recPill").className="pill run";
    $("recVerdict").textContent="—"; $("recDrop").textContent="—";
    $("recPeak").textContent="—"; $("recAfter").textContent="—";
    $("recStart").disabled=true; $("recCancel").disabled=false;
    this.timer=setInterval(()=>{
      const el=Math.floor((Date.now()-this.t0)/1000);
      $("recTimer").textContent=`Прошло ${el}/60 с` + (this.firstHr?` · пик ${this.firstHr} bpm`:"") + " · стой спокойно, не ходи";
      if(el>=60) this.finish();
    },250);
    log("Тест восстановления: старт. Постой неподвижно 60 с.");
  },
  onHR(hr){
    if(this.state!=="run") return;
    if(this.firstHr===null) this.firstHr=hr;
    this.endHr=hr;
    $("recPeak").textContent=this.firstHr+" bpm";
    $("recAfter").textContent=hr+" bpm";
  },
  finish(){
    clearInterval(this.timer);
    this.state="done";
    const drop=this.firstHr!==null&&this.endHr!==null ? this.firstHr-this.endHr : null;
    $("recDrop").textContent=drop!==null?("−"+drop+" bpm"):"—";
    let v, cls;
    if(drop===null){ v="мало данных"; }
    else if(drop>=30){ v="Отличная форма ✓"; cls="ok"; }
    else if(drop>=20){ v="Хорошо"; cls="ok"; }
    else if(drop>=12){ v="Средне — лёгкая нагрузка допустима"; cls="warn-t"; }
    else { v="Не восстановился — отдых сегодня"; cls="bad"; }
    $("recVerdict").textContent=v; $("recVerdict").className="value "+(cls||"");
    $("recPill").textContent="готов"; $("recPill").className="pill";
    $("recStart").disabled=false; $("recCancel").disabled=true;
    $("recTimer").textContent="";
    log(`Тест восстановления: ${this.firstHr} → ${this.endHr} bpm (−${drop}). ${v}`);
  },
  cancel(){
    clearInterval(this.timer); this.state="idle";
    $("recPill").textContent="отменён"; $("recPill").className="pill";
    $("recStart").disabled=false; $("recCancel").disabled=true;
    $("recTimer").textContent="";
  }
};

/* ---------- стресс-монитор v1 ---------- */
const stress={
  on:false, lastTrigger:0,
  toggle(){
    this.on=!this.on;
    $("stressToggle").textContent=this.on?"Выключить монитор":"Включить монитор";
    $("stressPill").textContent=this.on?"вкл":"выкл";
    $("stressPill").className="pill"+(this.on?" run":"");
    if(this.on){
      log("Стресс-монитор вкл: HR>100 3 мин + шаги стоят → дыхание 4-7-8.");
      this.tick();
    } else $("stressMsg").textContent="";
  },
  tick(){
    if(!this.on) return;
    const t=Date.now();
    const win=hrHistory.filter(s=>s.t>t-3*60*1000);
    const stepsFresh=(t-lastStepsT)<120000;
    let msg=`окно ${Math.min(Math.floor((t-(win[0]?.t||t))/1000),180)}/180 с · шаги: ${lastSteps??"нет данных"}${stepsFresh?"":" (устарели)"}`;
    let alert=false;
    if(win.length>30){
      const high=win.filter(s=>s.hr>100).length;
      const ratio=high/win.length;
      msg=`HR>100: ${Math.round(ratio*100)}% окна · шаги: ${lastSteps??"—"}${stepsFresh?"":" (устарели)"}`;
      if(ratio>0.9 && stepsFresh && lastSteps!==null){
        const s0=this._stepsAt??lastSteps;
        this._stepsAt=lastSteps;
        if(lastSteps-s0<=2) alert=true;
      } else this._stepsAt=lastSteps;
    }
    if(alert && t-this.lastTrigger>10*60*1000){
      this.lastTrigger=t;
      $("stressMsg").innerHTML='<span class="bad">Похоже на стресс: пульс высокий, движения нет. Начни дыхание.</span>';
      log("СТРЕСС-ТРИГГЕР: HR высокий + шаги стоят → дыхание 4-7-8");
      breathe.start();
    } else if(t-this.lastTrigger>10*60*1000){
      $("stressMsg").textContent=msg;
    }
  }
};
setInterval(()=>stress.tick(), 5000);

/* ---------- детектор «вруна» ---------- */
const lie={
  state:"idle", base:[], react:[],
  start(){
    this.state="base"; this.base=[]; this.react=[];
    $("lieStart").disabled=true; $("lieAsk").disabled=true;
    $("lieMsg").textContent="Базовая линия: 10 секунд спокойно…";
    $("lieVerdict").textContent="—"; $("lieSpike").textContent="—";
    setTimeout(()=>{
      if(this.state!=="base") return;
      this.state="ask";
      $("lieAsk").disabled=false;
      const avg=Math.round(this.base.reduce((a,b)=>a+b,0)/this.base.length);
      const mx=Math.max(...this.base);
      $("lieBase").textContent=`${avg} / ${mx}`;
      $("lieMsg").textContent="База готова. Задай вопрос — и сразу жми «Вопрос задан». Измерение реакции: 10 с.";
      log(`Вруна: база ${avg} bpm (макс ${mx})`);
    },10000);
  },
  onHR(hr){
    if(this.state==="base") this.base.push(hr);
    else if(this.state==="react") this.react.push(hr);
  },
  ask(){
    if(this.state!=="ask") return;
    this.state="react"; this.react=[];
    $("lieAsk").disabled=true;
    $("lieMsg").textContent="Смотрим на пульс…";
    setTimeout(()=>{
      this.state="done";
      $("lieStart").disabled=false;
      if(!this.react.length){ $("lieMsg").textContent="Нет данных — замер на часах остановился?"; return; }
      const baseAvg=this.base.reduce((a,b)=>a+b,0)/this.base.length;
      const spike=Math.max(...this.react)-baseAvg;
      const mx=Math.max(...this.react);
      $("lieSpike").textContent=`+${Math.round(spike)} bpm (макс ${mx})`;
      let v,cls;
      if(spike>=10){ v="Сильная реакция! 😅"; cls="bad"; }
      else if(spike>=5){ v="Реакция есть 🤨"; cls="warn-t"; }
      else { v="Спокоен как удав 😐"; cls="ok"; }
      $("lieVerdict").textContent=v; $("lieVerdict").className="value "+cls;
      $("lieMsg").textContent="Готово. Шуточный тест — не полиграф 🙂";
      log(`Вруна: реакция +${Math.round(spike)} bpm. ${v}`);
    },10000);
  }
};

/* ---------- дыхание 4-7-8 ---------- */
const breathe={
  phases:[["Вдох…",4000],["Задержка…",7000],["Выдох…",8000]],
  i:0, running:false, timer:null,
  start(){
    $("breathe").classList.add("on");
    this.running=true; this.i=0;
    this.next();
  },
  next(){
    if(!this.running) return;
    const [name,dur]=this.phases[this.i];
    $("bphase").textContent=name;
    const circle=$("bcircle");
    circle.style.transition=`transform ${dur}ms ease-in-out`;
    // растёт на вдохе, держится, сжимается на выдохе
    circle.style.transform=`scale(${this.i===0?1.55:this.i===1?1.55:0.7})`;
    $("bhr").textContent=currentHR?`пульс сейчас: ${currentHR} bpm`:"запусти замер на часах — увидишь эффект";
    this.timer=setTimeout(()=>{ this.i=(this.i+1)%3; this.next(); }, dur);
  },
  stop(){
    this.running=false; clearTimeout(this.timer);
    $("breathe").classList.remove("on");
    $("bcircle").style.transform="scale(1)";
  }
};

/* ---------- фаззер ---------- */
const fuzzer={
  running:false, stopFlag:false, results:[],
  parseList(){
    return $("fuzzList").value.split("\n")
      .map(l=>l.replace(/#.*$/,"").trim())
      .filter(l=>l.length>0)
      .map(l=>{ try{ return {cmd:l, bytes:hexToBytes(l)}; }catch(e){ log(`Фаззер: пропуск строки «${l}» — ${e.message}`); return null; } })
      .filter(Boolean);
  },
  async run(){
    if(this.running) return;
    const cmds=this.parseList();
    if(!cmds.length){ log("Фаззер: список пуст."); return; }
    if(!activeTx){ log("Фаззер: сначала подключись к часам."); return; }
    this.running=true; this.stopFlag=false; this.results=[];
    $("fuzzRun").disabled=true; $("fuzzStop").disabled=false;
    const winMs=Math.max(300, +$("fuzzWindow").value||1500);
    const gapMs=Math.max(100, +$("fuzzInterval").value||400);
    const pill=$("fuzzPill"); pill.textContent="работает"; pill.className="pill run";
    log(`Фаззер: ${cmds.length} команд, окно ответа ${winMs} мс`);
    this.render();
    for(const {cmd,bytes} of cmds){
      if(this.stopFlag) break;
      pill.textContent=`→ ${cmd}`;
      const t0=Date.now();
      let sendErr=null;
      try{ await send(bytes); }catch(e){ sendErr=e.message; }
      await sleep(winMs);
      const resp=rxFeed.filter(r=>r.t>=t0 && !PERIODIC_OPS.has(r.op));
      this.results.push({cmd, err:sendErr, count:resp.length, samples:[...new Set(resp.map(r=>r.hex))].slice(0,4)});
      this.render();
      await sleep(gapMs);
    }
    const found=this.results.filter(r=>r.count>0 && !r.err);
    pill.textContent=this.stopFlag?"остановлен":`готово, откликов: ${found.length}`;
    pill.className="pill"+(found.length?" run":"");
    log(`Фаззер завершён. Команд с откликом: ${found.length}/${this.results.length}`);
    this.running=false;
    $("fuzzRun").disabled=false; $("fuzzStop").disabled=true;
  },
  stop(){ this.stopFlag=true; },
  render(){
    const rows=this.results.map(r=>{
      const mark=r.err?`<span class="bad">ERR</span>`:r.count>0?`<span class="ok">OK×${r.count}</span>`:`<span class="muted">тишина</span>`;
      const samp=r.samples&&r.samples.length?`<code>${r.samples.join("<br>")}</code>`:"";
      return `<tr><td><code>${r.cmd}</code></td><td>${mark}${r.err?`<br><span class="bad">${r.err}</span>`:""}</td><td>${samp}</td></tr>`;
    }).join("");
    $("fuzzOut").innerHTML=`<table class="tbl"><tr><th>Команда</th><th>Отклик</th><th>Образцы RX</th></tr>${rows}</table>`;
  }
};


/* ---------- KW66 protocol / motion lab ---------- */
const protocolLab = {
  packets: [], sniffing:false, timer:null, phase:"REST", startedAt:0, maxPackets:12000,
  recordMotion(bytes,uuid){
    if(!this.sniffing) return;
    const t=Date.now(), op=bytes[0];
    this.packets.push({t,iso:new Date(t).toISOString(),direction:"RX",uuid:labelFor(uuid),hex:hex(bytes),op,phase:this.phase});
    if(this.packets.length>this.maxPackets)this.packets.shift();
    this.render();
  },
  render(){
    const counts={};
    for(const r of this.packets){const o=r.hex.split(" ")[0];counts[o]=(counts[o]||0)+1;}
    const unique=Object.keys(counts).length;
    $("motionCount").textContent=unique;
    const sum=Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([o,n])=>`<span class="pill">${o} ×${n}</span>`).join(" ");
    const rows=this.packets.slice(-220).map(r=>`<div><span class="muted">${new Date(r.t).toLocaleTimeString([], {hour12:false})}.${String(r.t%1000).padStart(3,"0")}</span> <code>${r.hex}</code> <span class="muted">${r.phase}</span></div>`).join("");
    $("motionOut").innerHTML=`<div style="margin-bottom:6px">${sum||'<span class="muted">нет RX</span>'}</div>${rows}`;
  },
  async cmd(bytes,label,experimental=false){
    if(this.sniffing){log("Protocol Lab: команда заблокирована во время Sniffer — нужен чистый RX.");return;}
    if(experimental&&!confirm(`${label}\n\nЭкспериментальная команда. Это не доказанный raw accelerometer-путь. Продолжить?`))return;
    try{await send(bytes);log(`Protocol Lab: ${label} → ${hex(bytes)}`);}catch(e){log(`Protocol Lab ERROR (${label}): ${e.message}`);}
  },
  start(){
    if(this.sniffing)return;
    this.sniffing=true;this.packets=[];this.phase="REST";this.startedAt=Date.now();
    $("motionPill").textContent="REST — 60 с";$("motionPill").className="pill run";
    ["motionRest","motionMove","motionShake"].forEach(id=>$(id).disabled=false);
    this.render();
    log("Motion Sniffer: старт 60 с. Команды не отправляются; пишется весь RX.");
    this.timer=setTimeout(()=>this.stop(),60000);
  },
  setPhase(phase){
    if(!this.sniffing)return;
    this.phase=phase;
    const elapsed=Math.floor((Date.now()-this.startedAt)/1000), left=Math.max(0,60-elapsed);
    $("motionPill").textContent=`${phase} — ${left} с`;
    log(`Motion Sniffer: маркер ${phase} на ${elapsed}.с`);
    this.render();
  },
  stop(){
    if(!this.sniffing)return;
    this.sniffing=false;if(this.timer)clearTimeout(this.timer);this.timer=null;
    ["motionRest","motionMove","motionShake"].forEach(id=>$(id).disabled=true);
    $("motionPill").textContent="готов";$("motionPill").className="pill";
    const counts={};for(const r of this.packets){const o=r.hex.split(" ")[0];counts[o]=(counts[o]||0)+1;}
    log(`Motion Sniffer: завершён. RX=${this.packets.length}; opcode=${Object.keys(counts).length}; CB=${counts.CB||0}; 31=${counts["31"]||0}; B1=${counts.B1||0}; A2=${counts.A2||0}.`);
    this.render();
  },
  exportCorrelation(){
    const counts={};for(const r of this.packets){const o=r.hex.split(" ")[0];counts[o]=(counts[o]||0)+1;}
    const phases={};for(const r of this.packets){(phases[r.phase]??=[]).push(r);}
    const summary={};for(const [ph,arr] of Object.entries(phases)){summary[ph]={packets:arr.length,opcodes:[...new Set(arr.map(x=>x.hex.split(" ")[0]))]};}
    const blob=new Blob([JSON.stringify({version:"KW66 Lab v3.6",createdAt:new Date().toISOString(),experiment:"60s full RX sniffer",note:"Manual phases REST/MOVE/REST/SHAKE; no commands are sent during sniffing",counts,phases:summary,packets:this.packets},null,2)],{type:"application/json"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`kw66-motion-sniff-${Date.now()}.json`;a.click();URL.revokeObjectURL(a.href);
  },
  clear(){if(this.sniffing)this.stop();this.packets=[];$("motionCount").textContent="0";$("motionOut").innerHTML="";$("motionPill").textContent="готов";}
};

const protocolSafe = {
  async a1(){ await protocolLab.cmd([0xA1],"A1 — модель/серийник"); },
  async a2(){ await protocolLab.cmd([0xA2],"A2 — батарея"); },
  async a3(){ await protocolLab.cmd([0xA3],"A3 — время"); },
  async b2(){ await protocolLab.cmd([0xB2,0xFA],"B2 FA — история шагов"); }
};

function updateProtocolUi(){
  $("protoTx").textContent=txChars.map(c=>labelFor(c.uuid)).join(", ")||"—";
  $("protoRx").textContent=rxCharsAll.map(c=>labelFor(c.uuid)).join(", ")||"—";
  $("protoRxCount").textContent=rxCount;
}

/* ---------- btsnoop-парсер ---------- */
const snoop={
  rows:[], txAgg:new Map(), parsed:null,
  async handleFile(file){
    try{
      const buf=await file.arrayBuffer();
      this.parse(buf);
      this.renderSummary();
      this.renderRows();
      $("snoopExport").disabled=false;
    }catch(e){ log(`Snoop ERROR: ${e.message}`); $("snoopSummary").innerHTML=`<span class="bad">Ошибка парсинга: ${e.message}</span>`; }
  },
  u32(dv,o){ return dv.getUint32(o,false); },
  u16at(a,o){ return (a[o]<<8)|a[o+1]; },
  u16le(a,o){ return a[o]|(a[o+1]<<8); },   // BLE: L2CAP/ATT поля — little-endian
  u64raw(dv,o){ return {hi:dv.getUint32(o,false), lo:dv.getUint32(o+4,false)}; },
  parse(buf){
    const magic=new Uint8Array(buf,0,8);
    if(String.fromCharCode(...magic)!=="btsnoop\0") throw new Error("не btsnoop-файл (нет магии btsnoop\\0)");
    const dv=new DataView(buf);
    const version=this.u32(dv,8), datalink=this.u32(dv,12);
    log(`Snoop: версия ${version}, datalink ${datalink}`);
    let off=16, firstTs=null, rows=[];
    const handleUuid={};
    while(off+24<=buf.byteLength){
      const inclLen=this.u32(dv,off+4), flags=this.u32(dv,off+8);
      const ts=this.u64raw(dv,off+16);
      if(firstTs===null) firstTs={...ts};
      const deltaUs=(ts.hi-firstTs.hi)*4294967296 + (ts.lo-firstTs.lo);
      const data=new Uint8Array(buf,off+24,inclLen);
      off+=24+inclLen;
      const type=data[0];
      if(type!==1 && type!==2 && type!==3 && type!==4) continue; // не HCI UART кадр
      const dir=(type===1||type===2)?"TX":"RX"; // с точки зрения телефона
      const rel=(deltaUs/1000).toFixed(0);
      if(type===1){ // HCI command
        const op=this.u16le(data,1), len=data[3];
        rows.push({t:rel, dir, kind:"HCI", op:"CMD 0x"+op.toString(16).toUpperCase().padStart(4,"0"), handle:null, uuid:null, value:hex(data.slice(4,4+len))});
        continue;
      }
      if(type!==2 && type!==4) continue; // HCI event (0x03) — пропускаем
      if(data.length<9) continue;
      const aclLen=this.u16le(data,3);
      const l2capLen=this.u16le(data,5);
      const cid=this.u16le(data,7);
      if(cid!==0x0004) continue; // только ATT
      const att=data.slice(9, Math.min(9+l2capLen, data.length));
      if(!att.length) continue;
      const aop=att[0];
      let kind=null, handle=null, value="";
      switch(aop){
        case 0x02: kind="MTU req"; value=""+this.u16le(att,1); break;
        case 0x03: kind="MTU resp"; value=""+this.u16le(att,1); break;
        case 0x04: kind="FindInfo req"; handle=this.u16le(att,1); break;
        case 0x05: { // FindInfo resp → handle→UUID
          kind="FindInfo resp";
          const fmt=att[1], sz=fmt===1?4:18;
          for(let i=2;i+sz<=att.length;i+=sz){
            const h=this.u16le(att,i);
            let uuid;
            if(fmt===1){ uuid="0000"+this.u16le(att,i+2).toString(16).padStart(4,"0")+"-0000-1000-8000-00805f9b34fb"; }
            else { uuid=hex(att.slice(i+2,i+18)).toLowerCase().replace(/^(.{8}) (.{4}) (.{4}) (.{4}) (.{12})$/,"$1-$2-$3-$4-$5"); }
            handleUuid[h]=uuid;
          }
          break; }
        case 0x10: kind="ReadByGroup req"; break;
        case 0x11: { // ReadByGroup resp → диапазоны сервисов
          kind="ReadByGroup resp";
          const e=att[1];
          for(let i=2;i+e<=att.length;i+=e){
            const h1=this.u16le(att,i), h2=this.u16le(att,i+2);
            let uuid;
            if(e===6) uuid="0000"+this.u16le(att,i+4).toString(16).padStart(4,"0")+"-0000-1000-8000-00805f9b34fb";
            else uuid=hex(att.slice(i+4,i+e)).toLowerCase().replace(/^(.{8}) (.{4}) (.{4}) (.{4}) (.{12})$/,"$1-$2-$3-$4-$5");
            handleUuid[h1]=uuid;
          }
          break; }
        case 0x08: kind="ReadByType req"; handle=this.u16le(att,1); break;
        case 0x09: kind="ReadByType resp"; break;
        case 0x0A: kind="Read req"; handle=this.u16le(att,1); break;
        case 0x0B: kind="Read resp"; handle=this.u16le(att,1); value=hex(att.slice(2)); break;
        case 0x12: kind="Write req"; handle=this.u16le(att,1); value=hex(att.slice(3)); break;
        case 0x13: kind="Write resp"; handle=this.u16le(att,1); break;
        case 0x52: kind="Write cmd"; handle=this.u16le(att,1); value=hex(att.slice(3)); break;
        case 0x1B: kind="Notify"; handle=this.u16le(att,1); value=hex(att.slice(3)); break;
        case 0x1E: kind="PrepWrite"; handle=this.u16le(att,1); value=hex(att.slice(5)); break;
        case 0x1F: kind="PrepWrite resp"; break;
        case 0x01: kind="Error resp"; handle=this.u16le(att,2); value="req 0x"+att[1].toString(16)+" err 0x"+att[4].toString(16); break;
        default: kind="ATT 0x"+aop.toString(16); break;
      }
      rows.push({t:rel, dir, kind, op:null, handle, uuid:handle!==null?(handleUuid[handle]||null):null, value});
    }
    // агрегация уникальных TX-записей
    const txAgg=new Map();
    rows.forEach((r,i)=>{
      if(r.dir==="TX" && (r.kind==="Write cmd"||r.kind==="Write req") && r.value){
        const key=(r.handle??"?")+"|"+r.value;
        if(!txAgg.has(key)) txAgg.set(key,{handle:r.handle, uuid:r.uuid, value:r.value, count:0, first:i, t:r.t});
        txAgg.get(key).count++;
      }
    });
    this.rows=rows; this.txAgg=txAgg; this.parsed={version, datalink};
    log(`Snoop: ${rows.length} ATT/HCI записей, ${txAgg.size} уникальных TX-записей`);
  },
  renderSummary(){
    const tx=[...this.txAgg.values()].sort((a,b)=>a.first-b.first);
    const list=tx.slice(0,40).map(e=>
      `<tr><td>${e.t}с</td><td>h${e.handle??"?"}</td><td>${e.uuid?`<code>${e.uuid.slice(0,8)}</code>`:"—"}</td><td><code>${e.value}</code></td><td>×${e.count}</td></tr>`
    ).join("");
    $("snoopSummary").innerHTML=`
      <div class="grid">
        <div><div class="label">Записей ATT/HCI</div><div class="value" style="font-size:18px">${this.rows.length}</div></div>
        <div><div class="label">Уникальных TX-команд</div><div class="value" style="font-size:18px">${this.txAgg.size}</div></div>
      </div>
      <div class="muted" style="margin:8px 0 4px">Команды, которые приложение шлёт часам (по времени первой отправки):</div>
      <table class="tbl"><tr><th>t</th><th>hnd</th><th>UUID</th><th>value</th><th>n</th></tr>${list}</table>
      ${tx.length>40?`<div class="muted">…и ещё ${tx.length-40}</div>`:""}`;
  },
  renderRows(){
    const gfOnly=$("snoopGF").checked;
    const flt=($("snoopFilter").value||"").replace(/[^0-9a-f]/gi,"").toUpperCase();
    let rows=this.rows;
    if(gfOnly) rows=rows.filter(r=>r.uuid && GF_KEYS.some(k=>r.uuid.toLowerCase().includes(k)));
    if(flt) rows=rows.filter(r=>r.value && r.value.replace(/ /g,"").includes(flt));
    const cap=1500;
    const shown=rows.slice(0,cap).map(r=>
      `<tr><td>${r.t}</td><td class="${r.dir==="TX"?"ok":"warn-t"}">${r.dir}</td><td>${r.kind}${r.op?" "+r.op:""}</td><td>${r.handle!==null?"h"+r.handle:""}</td><td>${r.uuid?`<code>${r.uuid.slice(0,8)}</code>`:""}</td><td><code>${r.value||""}</code></td></tr>`
    ).join("");
    $("snoopOut").innerHTML=`<table class="tbl"><tr><th>t,мс</th><th>dir</th><th>op</th><th>hnd</th><th>uuid</th><th>value</th></tr>${shown}</table>
      ${rows.length>cap?`<div class="muted">показано ${cap} из ${rows.length} — уточни фильтр</div>`:""}`;
  },
  export(){
    if(!this.rows.length) return;
    const data={parsedAt:new Date().toISOString(), file:this.parsed, uniqueTx:[...this.txAgg.values()], rows:this.rows};
    const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});
    const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download="kw66-snoop-parsed.json"; a.click(); URL.revokeObjectURL(a.href);
  }
};

/* ---------- привязка UI ---------- */
$("connect").onclick=connect;
$("disconnect").onclick=async()=>{ try{ if(device?.gatt?.connected) device.gatt.disconnect(); }catch{} };
$("clear").onclick=()=>{ $("log").textContent=""; logRows=[]; rxCount=0; rxBuffers={}; };
$("export").onclick=()=>{
  const blob=new Blob([JSON.stringify({device:device?.name||null,exportedAt:new Date().toISOString(),packets:logRows},null,2)],{type:"application/json"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download="kw66-log.json"; a.click(); URL.revokeObjectURL(a.href);
};
$("battery").onclick=readBattery;
$("steps").onclick=()=>send([0xB2,0xFA]).catch(e=>log(`Steps ERROR: ${e.message}`));
$("hrReq").onclick=()=>send([0xE5,0x00]).catch(e=>log(`HR ERROR: ${e.message}`));
$("sendCustom").onclick=()=>{ try{ send(hexToBytes($("custom").value)); }catch(e){ log(`CUSTOM ERROR: ${e.message}`); } };
$("sendWatchText").onclick=()=>{
  const idHex=($("watchTextId").value||"01").trim();
  const id=parseInt(idHex,16);
  sendWatchText($("watchText").value, isNaN(id)?0x01:id).catch(e=>log(`TEXT ERROR: ${e.message}`));
};
$("recStart").onclick=()=>recovery.start();
$("recCancel").onclick=()=>recovery.cancel();
$("stressToggle").onclick=()=>stress.toggle();
$("breatheOpen").onclick=()=>breathe.start();
$("breatheClose").onclick=()=>breathe.stop();
$("lieStart").onclick=()=>lie.start();
$("lieAsk").onclick=()=>lie.ask();
$("fuzzRun").onclick=()=>fuzzer.run();
$("fuzzStop").onclick=()=>fuzzer.stop();
$("snoopFile").onchange=e=>{ const f=e.target.files[0]; if(f) snoop.handleFile(f); };
$("snoopGF").onchange=()=>snoop.renderRows();
$("snoopFilter").oninput=()=>snoop.renderRows();
$("snoopExport").onclick=()=>snoop.export();
$("protoA1").onclick=()=>protocolSafe.a1();
$("protoA2").onclick=()=>protocolSafe.a2();
$("protoA3").onclick=()=>protocolSafe.a3();
$("protoB2").onclick=()=>protocolSafe.b2();
$("motionC401").onclick=()=>protocolLab.cmd([0xC4,0x01],"C4 01 — camera/gesture candidate",true);
$("motionC402").onclick=()=>protocolLab.cmd([0xC4,0x02],"C4 02 — camera/gesture candidate",true);
$("motionC403").onclick=()=>protocolLab.cmd([0xC4,0x03],"C4 03 — camera/gesture candidate",true);
$("motionD700").onclick=()=>protocolLab.cmd([0xD7,0x00],"D7 00 — DND candidate",true);
$("motionD701").onclick=()=>protocolLab.cmd([0xD7,0x01],"D7 01 — DND candidate",true);
$("motionD702").onclick=()=>protocolLab.cmd([0xD7,0x02],"D7 02 — DND candidate",true);
$("motionSniff").onclick=()=>protocolLab.sniffing?protocolLab.stop():protocolLab.start();
$("motionRest").onclick=()=>protocolLab.setPhase("REST");
$("motionMove").onclick=()=>protocolLab.setPhase("MOVE");
$("motionShake").onclick=()=>protocolLab.setPhase("SHAKE");
$("motionClear").onclick=()=>protocolLab.clear();
$("motionExport").onclick=()=>protocolLab.exportCorrelation();


setConnected(false);
updateProtocolUi();
if("serviceWorker" in navigator){
  navigator.serviceWorker.register("./sw.js").then(()=>log("Service Worker: OK")).catch(e=>log(`SW ERROR: ${e.message}`));
}
log(`Web Bluetooth: ${navigator.bluetooth ? "доступен" : "недоступен"}`);
