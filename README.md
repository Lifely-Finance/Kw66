# KW66 Lab v2.2

PWA для исследования IMILAB KW66 / GloryFit через Web Bluetooth.

## GitHub Pages

1. Распаковать проект.
2. Загрузить **содержимое** папки в репозиторий GitHub.
3. В Settings → Pages выбрать `Deploy from a branch`, branch `main`, folder `/ (root)`.
4. Открыть полученный HTTPS-адрес в Chrome Android.

## Что умеет

- requestDevice с `acceptAllDevices`;
- подключение GATT;
- перечисление primary services и characteristics;
- распознавание GloryFit UUID;
- включение notifications;
- RAW TX/RX HEX logging;
- Battery `A2`;
- Heart Rate `E5 00`;
- Steps `B2 FA`;
- Custom HEX command;
- экспорт JSON.

## Известные GloryFit UUID

- Service BLE4: `000055ff-0000-1000-8000-00805f9b34fb`
- Service BLE5: `000056ff-0000-1000-8000-00805f9b34fb`
- TX BLE4: `000033f1-0000-1000-8000-00805f9b34fb`
- RX BLE4: `000033f2-0000-1000-8000-00805f9b34fb`
- TX BLE5: `000034f1-0000-1000-8000-00805f9b34fb`
- RX BLE5: `000034f2-0000-1000-8000-00805f9b34fb`
- Alt TX: `0000b003-0000-1000-8000-00805f9b34fb`
- Alt RX: `0000b004-0000-1000-8000-00805f9b34fb`
- Battery: `00002a19-0000-1000-8000-00805f9b34fb`

## Важно

`Custom HEX` позволяет отправлять произвольные команды. Не отправляй неизвестные команды массово: сначала фиксируем TX/RX и сопоставляем ответ с известным действием часов.
