const UUID = {
  service4: "000055ff-0000-1000-8000-00805f9b34fb",
  service5: "000056ff-0000-1000-8000-00805f9b34fb",
  tx4: "000033f1-0000-1000-8000-00805f9b34fb",
  rx4: "000033f2-0000-1000-8000-00805f9b34fb",
  tx5: "000034f1-0000-1000-8000-00805f9b34fb",
  rx5: "000034f2-0000-1000-8000-00805f9b34fb",
  txAlt: "0000b003-0000-1000-8000-00805f9b34fb",
  rxAlt: "0000b004-0000-1000-8000-00805f9b34fb",
  battery: "00002a19-0000-1000-8000-00805f9b34fb"
};
const LABELS = {
  [UUID.rx4]: "BLE4", [UUID.tx4]: "BLE4",
  [UUID.rx5]: "BLE5", [UUID.tx5]: "BLE5",
  [UUID.rxAlt]: "ALT", [UUID.txAlt]: "ALT",
  [UUID.battery]: "BAT"
};
function labelFor(uuid){ return LABELS[uuid?.toLowerCase()] || uuid; }

let device=null, server=null, txChars=[], rx=null, batteryChar=null, activeTx=null;
let logRows=[], rxCount=0;
// буфер незавершённых фрагментов, отдельный на каждую characteristic (по uuid)
let rxBuffers={};

const $ = id => document.getElementById(id);
function now(){return new Date().toLocaleTimeString();}
function log(s){
  const line=`[${now()}] ${s}`;
  $("log").textContent += ( $("log").textContent ? "\n" : "" ) + line;
  $("log").scrollTop=$("log").scrollHeight;
}
function hex(data){
  return [...new Uint8Array(data)].map(x=>x.toString(16).padStart(2,"0").toUpperCase()).join(" ");
}
function hexToBytes(s){
  const clean=s.replace(/0x/gi,"").replace(/[^0-9a-f]/gi,"");
  if(clean.length===0 || clean.length%2) throw new Error("Некорректный HEX");
  const out=new Uint8Array(clean.length/2);
  for(let i=0;i<out.length;i++) out[i]=parseInt(clean.slice(i*2,i*2+2),16);
  return out;
}
function setEnabled(v){
  ["battery","hr","steps","sendCustom"].forEach(id=>$(id).disabled=!v);
}
function record(direction, bytes, sourceUuid){
  const value=hex(bytes.buffer || bytes);
  logRows.push({time:new Date().toISOString(),direction,hex:value,source:sourceUuid?labelFor(sourceUuid):undefined});
  if(direction==="RX"){
    rxCount++; $("rxCount").textContent=rxCount; $("lastRx").textContent=value;
  } else $("lastTx").textContent=value;
}
function looksLike(uuid, target){return uuid.toLowerCase()===target.toLowerCase();}
function characteristicProps(c){
  const p=c.properties || {};
  const out=[];
  if(p.read) out.push("read");
  if(p.write) out.push("write");
  if(p.writeWithoutResponse) out.push("writeWithoutResponse");
  if(p.notify) out.push("notify");
  if(p.indicate) out.push("indicate");
  return out.join(", ") || "—";
}
function findAllTx(candidates){
  return candidates.filter(c=>c.properties?.write || c.properties?.writeWithoutResponse);
}
function findAllRx(candidates){
  return candidates.filter(c=>c.properties?.notify || c.properties?.indicate);
}

// --- Сборка фрагментированных пакетов ---
// Каждой характеристике соответствует свой буфер, т.к. фрагменты одного
// логического пакета могут прийти двумя отдельными notify-эвентами
// (пример из реального лога: "A2" и "64" пришли раздельно).
// Известные форматы (opcode -> ожидаемая длина); B2 — переменной длины,
// поэтому для него определяем длину по второму байту.
const KNOWN_LEN = { 0xA2: 2, 0xA3: 8, 0xE5: 4, 0xF7: 9 };
function expectedLength(buf){
  const op = buf[0];
  if(op in KNOWN_LEN) return KNOWN_LEN[op];
  if(op === 0xB1){
    if(buf.length < 2) return null;
    return 18; // realtime steps — та же раскладка, что и у B2-истории
  }
  if(op === 0xB2){
    if(buf.length < 2) return null; // нужно больше данных, чтобы понять тип
    if(buf[1] === 0xFD) return 3;             // терминатор истории "B2 FD F5"
    if(buf[1] === 0x07) return 18;            // запись истории (год начинается с 0x07)
    return 2;                                  // ack-подобные короткие ответы
  }
  return null; // неизвестный opcode — сбрасываем как есть, без буферизации
}
function pushToBuffer(uuid, bytes){
  const key = uuid || "unknown";
  const prev = rxBuffers[key] || new Uint8Array(0);
  const merged = new Uint8Array(prev.length + bytes.length);
  merged.set(prev,0); merged.set(bytes, prev.length);
  rxBuffers[key] = merged;
  flushBuffer(key, uuid);
}
function flushBuffer(key, uuid){
  let buf = rxBuffers[key];
  while(buf && buf.length){
    const need = expectedLength(buf);
    if(need === null){
      // либо неизвестный opcode, либо нужно больше байт для B2/E5 —
      // если буфер уже подозрительно длинный, сбрасываем как "unknown blob"
      if(buf.length >= 20){
        emitPacket(buf, uuid, true);
        buf = new Uint8Array(0);
      }
      break;
    }
    if(buf.length < need) break; // ждём остальные фрагменты
    emitPacket(buf.slice(0, need), uuid, false);
    buf = buf.slice(need);
  }
  rxBuffers[key] = buf;
}
function emitPacket(bytes, uuid, isUnknownBlob){
  record("RX", bytes, uuid);
  if(isUnknownBlob) log(`  ⚠ несобранный фрагмент (${labelFor(uuid)}): ${hex(bytes)}`);
  else decodePacket(bytes, uuid);
}

function decodePacket(b, uuid){
  if(!b.length) return;
  const src = uuid ? `[${labelFor(uuid)}] ` : "";
  const op=b[0];
  if(op===0xE5 && b.length===4){
    const mode=b[1], hr=b[3];
    const modeLabel = mode===0x11 ? "идёт измерение" : (mode===0x00 ? "финальное значение" : `режим 0x${mode.toString(16)}`);
    if(hr>=40 && hr<=200) log(`  ↳ ${src}E5 (${modeLabel}): пульс = ${hr} bpm`);
    else log(`  ↳ ${src}E5: byte[3]=${hr} вне диапазона HR (${modeLabel})`);
  }
  if(op===0xA2) log(`  ↳ ${src}A2: батарея = ${b[1]}%`);
  if(op===0xF7 && b.length===9){
    const year=(b[2]<<8)|b[3];
    log(`  ↳ ${src}F7 (sub ${b[1]}): время часов ≈ ${year}-${pad(b[4])}-${pad(b[5])} ${pad(b[6])}:${pad(b[7])}`);
  }
  if(op===0xA3 && b.length>=8){
    const year=(b[1]<<8)|b[2];
    log(`  ↳ ${src}A3: время часов = ${year}-${pad(b[3])}-${pad(b[4])} ${pad(b[5])}:${pad(b[6])}:${pad(b[7])}`);
  }
  if(op===0xB1) log(`  ↳ ${src}B1: realtime steps packet`);
  if(op===0xB1 && b.length===18){
    const year=(b[1]<<8)|b[2], month=b[3], day=b[4], hour=b[5];
    const val = (b[6]<<8)|b[7];
    log(`  ↳ ${src}B1 realtime: ${year}-${pad(month)}-${pad(day)} ${pad(hour)}:xx → счётчик=${val}`);
  }
  if(op===0xB2){
    if(b.length===18){
      const year=(b[1]<<8)|b[2], month=b[3], day=b[4], hour=b[5];
      const val = (b[6]<<8)|b[7];
      log(`  ↳ ${src}B2 история: ${year}-${pad(month)}-${pad(day)} ${pad(hour)}:00 → значение=${val} (сырые байты: ${hex(b.slice(6))})`);
    } else if(b.length===3 && b[1]===0xFD){
      log(`  ↳ ${src}B2: конец выгрузки истории`);
    } else {
      log(`  ↳ ${src}B2: короткий ответ/ack (${hex(b)})`);
    }
  }
}
function pad(n){ return n.toString().padStart(2,"0"); }

async function subscribe(c){
  if(!c) return;
  if(c.properties.notify || c.properties.indicate){
    await c.startNotifications();
    c.addEventListener("characteristicvaluechanged", e=>{
      const bytes=new Uint8Array(e.target.value.buffer.slice(0));
      pushToBuffer(c.uuid, bytes);
    });
    log(`Уведомления включены: ${c.uuid} [${labelFor(c.uuid)}]`);
  }
}
async function send(bytes, txOverride){
  const t = txOverride || activeTx;
  if(!t) throw new Error("TX characteristic не найдена");
  const data=bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if(t.properties.writeWithoutResponse && !t.properties.write){
    await t.writeValueWithoutResponse(data);
  } else {
    await t.writeValue(data);
  }
  record("TX",data, t.uuid);
  log(`TX → [${labelFor(t.uuid)}] ${hex(data)}`);
}
function renderTxSelect(){
  const sel = $("txSelect");
  if(!sel) return;
  sel.innerHTML = txChars.map((c,i)=>`<option value="${i}">${labelFor(c.uuid)} — ${c.uuid}</option>`).join("");
  sel.onchange = ()=>{ activeTx = txChars[Number(sel.value)]; log(`Активный TX переключён на [${labelFor(activeTx.uuid)}]`); };
}
async function connect(){
  if(!navigator.bluetooth){log("ОШИБКА: Web Bluetooth недоступен в этом браузере.");return;}
  try{
    log("Открываю системный BLE-выбор устройства.");
    device=await navigator.bluetooth.requestDevice({
      acceptAllDevices:true,
      optionalServices:[UUID.service4,UUID.service5,UUID.battery]
    });
    $("device").textContent=`Выбрано: ${device.name||"(без имени)"} (${device.id})`;
    device.addEventListener("gattserverdisconnected",()=>{
      log("GATT disconnected.");
      server=null; txChars=[]; activeTx=null; rx=null; batteryChar=null; rxBuffers={}; setEnabled(false);
    });
    server=await device.gatt.connect();
    log("GATT connected.");
    const services=await server.getPrimaryServices();
    log(`Найдено primary services: ${services.length}`);

    const chars=[];
    for(const s of services){
      log(`SERVICE ${s.uuid}`);
      const cs=await s.getCharacteristics();
      for(const c of cs){
        chars.push(c);
        log(`CHAR ${c.uuid} [${characteristicProps(c)}]`);
      }
    }

    const txCandidates=chars.filter(c=>looksLike(c.uuid,UUID.tx4)||looksLike(c.uuid,UUID.tx5)||looksLike(c.uuid,UUID.txAlt));
    const rxCandidates=chars.filter(c=>looksLike(c.uuid,UUID.rx4)||looksLike(c.uuid,UUID.rx5)||looksLike(c.uuid,UUID.rxAlt));
    txChars=findAllTx(txCandidates);
    const rxAll=findAllRx(rxCandidates);
    batteryChar=chars.find(c=>looksLike(c.uuid,UUID.battery));

    activeTx = txChars[0] || null;
    $("txChar").textContent=txChars.map(c=>labelFor(c.uuid)).join(", ")||"не найден";
    $("rxChar").textContent=rxAll.map(c=>labelFor(c.uuid)).join(", ")||"не найден";
    renderTxSelect();

    if(txChars.length || rxAll.length){
      $("profile").innerHTML='<span class="ok">GloryFit распознан</span>';
      log(`Профиль GloryFit распознан. TX-каналов: ${txChars.length}, RX-каналов: ${rxAll.length}`);
    } else {
      $("profile").innerHTML='<span class="bad">GloryFit не найден</span>';
    }

    // Подписываемся на ВСЕ найденные notify-каналы, а не только на первый —
    // ответ на команду (например HR) может прийти на другую характеристику,
    // чем та, куда ушёл запрос.
    for(const c of rxAll) await subscribe(c);
    if(batteryChar?.properties?.notify && !rxAll.length){
      await subscribe(batteryChar);
    }

    setEnabled(txChars.length>0);
  }catch(e){
    log(`ОШИБКА: ${e.name||"Error"}: ${e.message||e}`);
  }
}
async function readBattery(){
  try{
    if(batteryChar?.properties?.read){
      const v=await batteryChar.readValue();
      const b=new Uint8Array(v.buffer.slice(0));
      log(`BATTERY read ← ${hex(b.buffer)}`);
      record("RX",b, batteryChar.uuid);
    }else await send([0xA2]);
  }catch(e){log(`Battery ERROR: ${e.message}`);}
}
async function disconnect(){
  try{if(device?.gatt?.connected) device.gatt.disconnect();}catch{}
}
$("connect").onclick=connect;
$("disconnect").onclick=disconnect;
$("clear").onclick=()=>{$("log").textContent="";logRows=[];rxCount=0;rxBuffers={};$("rxCount").textContent="0";$("lastRx").textContent="—";$("lastTx").textContent="—";};
$("export").onclick=()=>{
  const blob=new Blob([JSON.stringify({device:device?.name||null,exportedAt:new Date().toISOString(),packets:logRows},null,2)],{type:"application/json"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download="kw66-log.json"; a.click(); URL.revokeObjectURL(a.href);
};
$("battery").onclick=readBattery;
$("hr").onclick=()=>send([0xE5,0x00]).catch(e=>log(`HR ERROR: ${e.message}`));
$("steps").onclick=()=>send([0xB2,0xFA]).catch(e=>log(`STEPS ERROR: ${e.message}`));
$("sendCustom").onclick=()=>{
  try{send(hexToBytes($("custom").value));}catch(e){log(`CUSTOM ERROR: ${e.message}`);}
};
if("serviceWorker" in navigator){
  navigator.serviceWorker.register("./sw.js").then(()=>log("Service Worker: OK")).catch(e=>log(`Service Worker ERROR: ${e.message}`));
}
log(`Web Bluetooth: ${navigator.bluetooth ? "доступен" : "недоступен"}`);
