-- KW66 Morse Messenger — схема Supabase
-- Выполнить целиком в SQL Editor проекта Supabase.

-- Таблица для одноразового обмена публичными ключами при pairing.
-- Живёт недолго: приложение удаляет строку сразу после того, как
-- обе стороны прочитали друг у друга публичный ключ.
create table if not exists pairs (
  id text primary key,           -- код приглашения, он же имя канала (~80 бит энтропии)
  pub_a text,                    -- публичный ключ инициатора (base64, ECDH P-256 raw)
  pub_b text,                    -- публичный ключ второго устройства
  created_at timestamptz not null default now()
);

-- Таблица транспорта сообщений. Сервер видит только шифротекст.
-- pair_id намеренно без FK на pairs — канал продолжает работать и
-- после того, как строка в pairs удалена.
create table if not exists relay (
  id bigserial primary key,
  pair_id text not null,
  from_role text not null check (from_role in ('a','b')),
  iv text not null,              -- base64, 12 байт
  ciphertext text not null,      -- base64, AES-256-GCM
  created_at timestamptz not null default now()
);

alter table pairs enable row level security;
alter table relay enable row level security;

-- Осознанное упрощение для лабораторного прототипа: секретность канала
-- держится на непредсказуемости pair_id (16 символов, ~80 бит) и на
-- том, что содержимое всё равно зашифровано end-to-end — RLS здесь не
-- защищает per-пользовательский доступ, а просто открывает anon-ключу
-- работу с этими двумя таблицами.
create policy "anon rw (capability secret = pair_id)" on pairs
  for all to anon using (true) with check (true);
create policy "anon rw (capability secret = pair_id)" on relay
  for all to anon using (true) with check (true);

-- Включить Realtime для таблицы relay (для мгновенной доставки без поллинга).
alter publication supabase_realtime add table relay;
alter publication supabase_realtime add table pairs;

-- Опционально: периодическая очистка "зависших" незавершённых pairing-строк
-- (например через pg_cron, если он включён на проекте):
-- select cron.schedule('cleanup-stale-pairs', '0 * * * *',
--   $$ delete from pairs where created_at < now() - interval '1 day' $$);
