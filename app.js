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

let device=null, server=null, tx=null, rx=null, batteryChar=null;
let logRows=[], rxCount=0;

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
function record(direction, bytes){
  const value=hex(bytes.buffer || bytes);
  logRows.push({time:new Date().toISOString(),direction,hex:value});
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
function findTx(candidates){
  return candidates.find(c=>c.properties?.write) ||
         candidates.find(c=>c.properties?.writeWithoutResponse) || null;
}
function findRx(candidates){
  return candidates.find(c=>c.properties?.notify) ||
         candidates.find(c=>c.properties?.indicate) || null;
}
async function subscribe(c){
  if(!c) return;
  if(c.properties.notify || c.properties.indicate){
    await c.startNotifications();
    c.addEventListener("characteristicvaluechanged", e=>{
      const b=new Uint8Array(e.target.value.buffer.slice(0));
      record("RX",b);
      decodePacket(b);
    });
    log(`Уведомления включены: ${c.uuid}`);
  }
}
function decodePacket(b){
  if(!b.length) return;
  const op=b[0];
  if(op===0xE5 && b.length>8){
    const hr=b[8];
    if(hr>=40 && hr<=200) log(`  ↳ E5: кандидат HR = ${hr} bpm`);
  }
  if(op===0xA2) log(`  ↳ A2: ответ батареи получен`);
  if(op===0xB1) log(`  ↳ B1: realtime steps packet`);
  if(op===0xB2) log(`  ↳ B2: steps/history packet`);
}
async function send(bytes){
  if(!tx) throw new Error("TX characteristic не найдена");
  const data=bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if(tx.properties.writeWithoutResponse && !tx.properties.write){
    await tx.writeValueWithoutResponse(data);
  } else {
    await tx.writeValue(data);
  }
  record("TX",data);
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
      server=null; tx=null; rx=null; batteryChar=null; setEnabled(false);
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

    tx=findTx(chars.filter(c=>looksLike(c.uuid,UUID.tx4)||looksLike(c.uuid,UUID.tx5)||looksLike(c.uuid,UUID.txAlt)));
    rx=findRx(chars.filter(c=>looksLike(c.uuid,UUID.rx4)||looksLike(c.uuid,UUID.rx5)||looksLike(c.uuid,UUID.rxAlt)));
    batteryChar=chars.find(c=>looksLike(c.uuid,UUID.battery));

    $("txChar").textContent=tx?.uuid||"не найден";
    $("rxChar").textContent=rx?.uuid||"не найден";

    if(tx || rx){
      $("profile").innerHTML='<span class="ok">GloryFit распознан</span>';
      log("Профиль GloryFit распознан.");
    } else {
      $("profile").innerHTML='<span class="bad">GloryFit не найден</span>';
    }

    await subscribe(rx);

    if(batteryChar?.properties?.notify && !rx){
      await subscribe(batteryChar);
    }

    setEnabled(!!tx);
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
      record("RX",b);
    }else await send([0xA2]);
  }catch(e){log(`Battery ERROR: ${e.message}`);}
}
async function disconnect(){
  try{if(device?.gatt?.connected) device.gatt.disconnect();}catch{}
}
$("connect").onclick=connect;
$("disconnect").onclick=disconnect;
$("clear").onclick=()=>{$("log").textContent="";logRows=[];rxCount=0;$("rxCount").textContent="0";$("lastRx").textContent="—";$("lastTx").textContent="—";};
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
