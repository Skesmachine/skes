# Вход через Telegram + Mini App — настройка

Серверная часть — Cloudflare Worker `worker.js` (эндпоинт `POST /telegram-auth`).
Он проверяет подпись Telegram и выдаёт одноразовый токен, которым сайт логинит
пользователя в Supabase. Токен бота и service-ключ хранятся ТОЛЬКО как секреты
Cloudflare — в браузер не попадают.

## 1. Бот в Telegram (@BotFather)
1. Откройте **@BotFather** → `/newbot` → задайте имя и @username бота. Получите **токен**.
2. `/newapp` (или `/myapps` → бот → **Web App / Mini App**):
   - URL Mini App: адрес сайта на Cloudflare, напр. `https://skes-mashina.<...>.workers.dev/`
     (или ваш домен).
   - Готово — у бота появится кнопка запуска Mini App.
3. (для входа из обычного браузера, необязательно) `/setdomain` → укажите домен сайта.

## 2. SQL в Supabase (SQL Editor)
```sql
create table if not exists tg_links (
  telegram_id bigint primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  username text,
  created_at timestamptz default now()
);
alter table tg_links enable row level security;
drop policy if exists "read own tg link" on tg_links;
create policy "read own tg link" on tg_links
  for select using (auth.uid() = user_id);
```
Запись/чтение всех строк делает только сервер под `service_role` (он минует RLS).

## 3. Секреты в Cloudflare
Cloudflare → Workers & Pages → **skes-mashina** → Settings → **Variables and Secrets**
→ добавьте три секрета (тип Secret):

| Имя | Значение |
|---|---|
| `BOT_TOKEN` | токен бота из @BotFather |
| `SUPABASE_URL` | `https://uckwmceuwjzjbawermgd.supabase.co` (ваш Project URL) |
| `SUPABASE_SERVICE_ROLE` | ключ **service_role** из Supabase → Settings → API. **Секрет!** |

После сохранения секретов сделайте редеплой (любой `git push` подойдёт).

## 4. Как это работает
- **Внутри Telegram (Mini App):** сайт сам входит по подписи `initData` — отдельная
  кнопка не нужна, но «Войти через Telegram» на странице входа тоже сработает.
- **Привязать к текущему аккаунту:** зайдите обычным логином/паролем, откройте свой
  профиль → «Привязать Telegram» (видно только внутри Mini App). После привязки этот
  Telegram логинит в тот же аккаунт.
- **Из обычного браузера** вход через Telegram отключён (нужна подпись из Telegram);
  при желании можно включить Telegram Login Widget — впишите @username бота в
  `TG_BOT_USERNAME` в `index.html` (тогда сервер уже умеет проверять и widget-подпись).

## 5. Проверка
- Открыть Mini App через бота → должно залогинить автоматически.
- `POST /telegram-auth` без тела вернёт `{"error":"bad_json"}` — значит Worker живой.
- Если `{"error":"server_not_configured"}` — не заданы секреты (шаг 3).
