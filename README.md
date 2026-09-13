# KW66 Lab v2.1 — PWA

PWA для диагностики и исследования IMILAB KW66 / GloryFit по Bluetooth Low Energy.

## Запуск

1. Загрузить **содержимое этой папки** в GitHub repository.
2. В GitHub: Settings → Pages → Deploy from branch → `main` → `/ (root)`.
3. Открыть выданный `https://USERNAME.github.io/REPOSITORY/` в Chrome на Android.
4. Нажать «Найти и подключить KW66».

Web Bluetooth требует HTTPS и поддерживаемого браузера. На Android используй актуальный Chrome.

## Что изменено в v2

- `acceptAllDevices: true`, потому что KW66/GloryFit может не рекламировать сервисный UUID в advertising packet.
- Явно запрашиваются GloryFit service UUID как `optionalServices`.
- Полное перечисление primary services и characteristics после подключения.
- Поиск GloryFit v1 и BLE5 UUID.
- Поддержка `write` и `writeWithoutResponse`.
- Поддержка `notify` и `indicate`.
- Автоматическое включение notifications.
- Отдельная диагностика Web Bluetooth / HTTPS.
- Счётчик RX-пакетов.
- Отображение всех найденных характеристик.
- Переподключение без нового выбора устройства, если браузер сохраняет разрешение.
- RAW HEX лог до 2000 строк + экспорт.
- Кандидат HR для пакетов `E5` по byte[8].
- Команды A2, E5 00, B2 FA.

## Важно для диагностики

Если Chrome **вообще не показывает KW66 в системном окне выбора Bluetooth**, проблема находится до уровня приложения: часы могут быть заняты приложением GloryFit/другим Bluetooth-соединением, быть не в режиме, который позволяет подключение, либо Android/Chrome не отдаёт их Web Bluetooth.

Если часы выбираются, но после подключения профиль GloryFit не находится, RAW/диагностический лог поможет определить реальный GATT-профиль именно твоего экземпляра KW66.

## GloryFit UUID

Service `000055ff-0000-1000-8000-00805f9b34fb`
Write `000033f1-0000-1000-8000-00805f9b34fb`
Notify `000033f2-0000-1000-8000-00805f9b34fb`
BLE5 Service `000056ff-0000-1000-8000-00805f9b34fb`
BLE5 Write `000034f1-0000-1000-8000-00805f9b34fb`
BLE5 Notify `000034f2-0000-1000-8000-00805f9b34fb`
