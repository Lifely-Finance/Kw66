const UUID={
 service:'000055ff-0000-1000-8000-00805f9b34fb', write:'000033f1-0000-1000-8000-00805f9b34fb', notify:'000033f2-0000-1000-8000-00805f9b34fb',
 service5:'000056ff-0000-1000-8000-00805f9b34fb', write5:'000034f1-0000-1000-8000-00805f9b34fb', notify5:'000034f2-0000-1000-8000-00805f9b34fb'
};
let device=null,server=null,writeChar=null,notifyChar=null,lines=[],rxCount=0,lastService=null;
const $=id=>document.getElementById(id);
const norm=s=>String(s).toLowerCase();
const hex=b=>Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join(' ').toUpperCase();
function log(s){const t=new Date().toLocaleTimeString();lines.push(`[${t}] ${s}`);if(lines.length>2000)lines.shift();$('log').textContent=lines.join('\n');$('log').scrollTop=$('log').scrollHeight;}
function diag(s,ok=true){const li=document.createElement('li');li.textContent=s;li.className=ok?'ok':'bad';$('diag').appendChild(li);}
function setStatus(text,cls=''){const el=$('status');el.textContent=text;el.className='pill '+cls;}
function setConnected(v){$('connect').disabled=v;$('disconnect').disabled=!v;$('reconnect').disabled=!device;['readBattery','readHr','readSteps'].forEach(id=>$(id).disabled=!v);$('gatt').textContent=v?'connected':'—';if(!v){$('profile').textContent='Не подключен';}}
function updateBrowser(){
 const supported=!!navigator.bluetooth; $('btState').textContent=supported?'доступен':'не доступен';
 if(!supported){$('browserWarning').textContent='Web Bluetooth не поддерживается этим браузером. Открой GitHub Pages именно в Chrome на Android.';$('browserWarning').classList.remove('hidden');diag('Web Bluetooth API не найден',false);return false;}
 if(!window.isSecureContext){$('browserWarning').textContent='Нужен HTTPS. GitHub Pages должен открываться с https://...';$('browserWarning').classList.remove('hidden');diag('Secure Context отсутствует',false);return false;}
 diag('Web Bluetooth доступен');diag('HTTPS / Secure Context OK');return true;
}
function onDisconnect(){log('GATT отключён');setStatus('Отключено','bad');server=null;writeChar=null;notifyChar=null;setConnected(false);}
function characteristicSummary(c){return `${c.uuid} [${[...c.properties].join(', ')}]`;}
async function inspectServices(){
 const services=await server.getPrimaryServices(); log(`Найдено primary services: ${services.length}`);
 let profileFound=false;
 $('profileBox').innerHTML='';
 for(const s of services){
   const block=document.createElement('div');block.className='service';
   const title=document.createElement('div');title.innerHTML=`<b>SERVICE</b> <code>${s.uuid}</code>`;block.appendChild(title);
   const chars=await s.getCharacteristics();
   for(const c of chars){
     log(`CHAR ${characteristicSummary(c)}`);
     const row=document.createElement('div');row.className='char';row.textContent=`${c.uuid} · ${[...c.properties].join(', ')}`;block.appendChild(row);
     const id=norm(c.uuid);
     if(id===UUID.write || id===UUID.write5){writeChar=c;lastService=s;profileFound=true;}
     if(id===UUID.notify || id===UUID.notify5){notifyChar=c;lastService=s;profileFound=true;}
   }
   $('profileBox').appendChild(block);
 }
 // Fallback: locate any writable + notifying characteristic inside known GloryFit services.
 if(!profileFound){
   for(const sid of [UUID.service,UUID.service5]){try{const s=await server.getPrimaryService(sid);const cs=await s.getCharacteristics();for(const c of cs){if(!writeChar&&(c.properties.write||c.properties.writeWithoutResponse))writeChar=c;if(!notifyChar&&(c.properties.notify||c.properties.indicate))notifyChar=c;}if(writeChar||notifyChar){lastService=s;profileFound=true;}}catch(e){}}
 }
 $('profile').textContent=profileFound?'найден':'не найден';
 return profileFound;
}
async function enableNotify(){
 if(!notifyChar){log('Notify/Indicate characteristic не найдена.');return false;}
 try{
   await notifyChar.startNotifications();
   notifyChar.addEventListener('characteristicvaluechanged',onNotify);
   log(`Уведомления включены: ${notifyChar.uuid}`);return true;
 }catch(e){log(`NOTIFY ERROR: ${e.message}`);return false;}
}
async function connect(){
 if(!updateBrowser())return;
 try{
   setStatus('Выбор устройства…');
   log('Открываю системный BLE-выбор устройства.');
   // acceptAllDevices is intentional: some KW66 firmware does not advertise the GloryFit service UUID.
   device=await navigator.bluetooth.requestDevice({acceptAllDevices:true,optionalServices:[UUID.service,UUID.service5,'battery_service']});
   device.addEventListener('gattserverdisconnected',onDisconnect);
   $('deviceName').textContent=device.name||'(без имени)';
   log(`Выбрано: ${device.name||'(без имени)'}`);
   setStatus('Подключение…');
   server=await device.gatt.connect();
   $('gatt').textContent='connected';
   log('GATT connected.');
   const found=await inspectServices();
   if(!found)log('GloryFit UUID не обнаружены. Это важно: пришли лог из раздела RAW/диагностики, не отправляя команды.');
   const notified=await enableNotify();
   setConnected(true);setStatus(notified?'Готово':'Подключено','ok');
   if(found)log('Профиль GloryFit распознан.');
 }catch(e){
   if(e.name==='NotFoundError'){log('Выбор устройства отменён пользователем.');setStatus('Отменено');return;}
   log(`ОШИБКА: ${e.name||'Error'}: ${e.message}`);setStatus('Ошибка','bad');setConnected(false);
 }
}
async function reconnect(){if(!device){return connect();}try{setStatus('Переподключение…');server=await device.gatt.connect();$('gatt').textContent='connected';writeChar=null;notifyChar=null;await inspectServices();await enableNotify();setConnected(true);setStatus('Готово','ok');}catch(e){log(`RECONNECT ERROR: ${e.message}`);setStatus('Ошибка','bad');setConnected(false);}}
function onNotify(ev){const v=ev.target.value;const h=hex(v.buffer);rxCount++;$('rxCount').textContent=rxCount;log(`RX ${h}`);const a=new Uint8Array(v.buffer);if(a[0]===0xE5&&a.length>8){const hr=a[8];if(hr>=40&&hr<=200){$('hr').textContent=hr+' bpm';log(`  → кандидат HR: ${hr} bpm`);}}}
async function send(bytes,label){
 if(!writeChar){log('Write characteristic не найдена. Команда не отправлена.');return;}
 try{const data=new Uint8Array(bytes);if(writeChar.properties.writeWithoutResponse&&!writeChar.properties.write){await writeChar.writeValueWithoutResponse(data);}else if(writeChar.properties.write){await writeChar.writeValue(data);}else{throw new Error('характеристика не поддерживает write');}log(`TX ${label}: ${hex(data)}`);}catch(e){log(`TX ERROR ${e.message}`);}
}
$('connect').onclick=connect;$('reconnect').onclick=reconnect;$('disconnect').onclick=()=>{if(device?.gatt?.connected)device.gatt.disconnect();else onDisconnect()};
$('readBattery').onclick=()=>send([0xA2],'A2');$('readHr').onclick=()=>send([0xE5,0x00],'E5 00');$('readSteps').onclick=()=>send([0xB2,0xFA],'B2 FA');
$('clear').onclick=()=>{lines=[];$('log').textContent='Очищено.';};$('export').onclick=()=>{const blob=new Blob([lines.join('\n')],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='kw66-ble-log-'+Date.now()+'.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
updateBrowser();
if('serviceWorker'in navigator)window.addEventListener('load',()=>navigator.serviceWorker.register('./sw.js').then(()=>log('Service Worker: OK')).catch(e=>log('Service Worker: '+e.message)));
