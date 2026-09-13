# KW66 Lab — PWA

PWA для исследования IMILAB KW66 / GloryFit по Bluetooth Low Energy.

## Важно
Web Bluetooth работает только в поддерживаемом браузере и в secure context: HTTPS (либо localhost). На Android для тестирования используй актуальный Chrome.

## Быстрый запуск на компьютере
1. Распакуй проект.
2. В папке проекта запусти любой локальный HTTP-сервер, например `python -m http.server 8000`.
3. Открой `http://localhost:8000` в Chrome.

Для телефона нужен HTTPS-хостинг (например GitHub Pages или другой статический хостинг). После публикации открой HTTPS-адрес в Chrome на Android и добавь страницу на главный экран.

## Что умеет первая версия
- выбор любого BLE-устройства;
- подключение GATT;
- перечисление сервисов и характеристик;
- поиск GloryFit service/characteristics;
- подписка на notifications;
- отображение RAW HEX;
- автоматическое определение кандидата HR для пакетов E5;
- команды A2 (battery), E5 00 (HR), B2 FA (steps);
- экспорт лога.

## GloryFit UUID
Service 000055ff-0000-1000-8000-00805f9b34fb
Write 000033f1-0000-1000-8000-00805f9b34fb
Notify 000033f2-0000-1000-8000-00805f9b34fb
BLE5 Service 000056ff-0000-1000-8000-00805f9b34fb
BLE5 Write 000034f1-0000-1000-8000-00805f9b34fb
BLE5 Notify 000034f2-0000-1000-8000-00805f9b34fb
