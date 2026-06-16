// Cloudflare Worker для «Скес машины».
// Раздаёт статический сайт (env.ASSETS) и обрабатывает вход через Telegram
// на эндпоинте POST /telegram-auth.
//
// СЕКРЕТЫ (Cloudflare → Workers → skes-mashina → Settings → Variables and Secrets):
//   BOT_TOKEN              — токен бота из @BotFather
//   SUPABASE_URL           — https://xxxx.supabase.co
//   SUPABASE_SERVICE_ROLE  — service_role ключ (Supabase → Settings → API). СЕКРЕТ! Только на сервере.
//
// Эндпоинт принимает JSON:
//   {action:'login', initData}                      — вход из Telegram Mini App
//   {action:'login', widget:{...}}                  — вход через Telegram Login Widget (браузер)
//   {action:'link',  initData, accessToken}         — привязать Telegram к текущему аккаунту
// и возвращает {ok, email, token_hash} (клиент делает verifyOtp) либо {ok, linked}.

const TG_MAX_AGE = 3600; // initData/widget не старше часа (защита от повторного входа)
const TG_EMAIL_DOMAIN = 'telegram.skesmachina.app';
const LOGIN_DOMAIN = '@skesmachina.app'; // логин-почта = slug(имя)@skesmachina.app
// имя профиля может быть кириллицей; почта входа — ASCII-транслит
const RU2LAT = {'а':'a','б':'b','в':'v','г':'g','д':'d','е':'e','ё':'e','ж':'zh','з':'z','и':'i','й':'i','к':'k','л':'l','м':'m','н':'n','о':'o','п':'p','р':'r','с':'s','т':'t','у':'u','ф':'f','х':'h','ц':'ts','ч':'ch','ш':'sh','щ':'sch','ъ':'','ы':'y','ь':'','э':'e','ю':'yu','я':'ya'};
function ruSlug(name){ return String(name || '').toLowerCase().trim().split('').map(c => RU2LAT[c] !== undefined ? RU2LAT[c] : c).join('').replace(/[^a-z0-9_]/g, ''); }

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/telegram-auth') return handleTelegramAuth(request, env);
    if (url.pathname === '/account-rename') return handleRename(request, env);
    if (url.pathname === '/account-claim') return handleClaim(request, env);
    return env.ASSETS.fetch(request);
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });
}
// глубина обороны: браузерные POST принимаем только со своего origin.
// у не-браузерных источников Origin нет — их пропускаем (всё равно нужна подпись/токен).
function originOk(request) {
  const o = request.headers.get('Origin');
  if (!o) return true;
  try { return new URL(o).host === new URL(request.url).host; } catch { return false; }
}
const enc = (s) => new TextEncoder().encode(s);

async function hmac(keyBytes, msg) {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc(msg)));
}
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
const toHex = (buf) => [...buf].map((b) => b.toString(16).padStart(2, '0')).join('');
function safeEqual(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }

// проверка подписи initData из Mini App (secret = HMAC("WebAppData", token))
async function verifyInitData(initData, botToken) {
  const p = new URLSearchParams(initData);
  const hash = p.get('hash'); if (!hash) return null;
  p.delete('hash');
  const dcs = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
  const secret = await hmac(enc('WebAppData'), botToken);
  if (!safeEqual(toHex(await hmac(secret, dcs)), hash)) return null;
  if ((Date.now() / 1000 - Number(p.get('auth_date') || 0)) > TG_MAX_AGE) return null;
  try { return JSON.parse(p.get('user') || 'null'); } catch { return null; }
}

// проверка подписи Telegram Login Widget (secret = SHA256(token))
async function verifyWidget(data, botToken) {
  const { hash, ...rest } = data || {};
  if (!hash) return null;
  const dcs = Object.keys(rest).filter((k) => rest[k] != null).sort().map((k) => `${k}=${rest[k]}`).join('\n');
  const secret = await sha256(enc(botToken));
  if (!safeEqual(toHex(await hmac(secret, dcs)), hash)) return null;
  if ((Date.now() / 1000 - Number(rest.auth_date || 0)) > TG_MAX_AGE) return null;
  return rest;
}

function sbHeaders(env) {
  return { apikey: env.SUPABASE_SERVICE_ROLE, authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE}`, 'content-type': 'application/json' };
}
async function findLink(env, tgId) {
  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/tg_links?telegram_id=eq.${tgId}&select=user_id,username`, { headers: sbHeaders(env) });
  const a = await r.json().catch(() => null);
  return Array.isArray(a) && a[0] ? a[0] : null;
}
async function getUserEmail(env, userId) {
  const r = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users/${userId}`, { headers: sbHeaders(env) });
  if (!r.ok) return null;
  const u = await r.json(); return u.email || null;
}
async function createUser(env, email, username) {
  const r = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
    method: 'POST', headers: sbHeaders(env),
    body: JSON.stringify({ email, email_confirm: true, user_metadata: { username } })
  });
  const u = await r.json();
  if (!r.ok) throw new Error(u.msg || u.message || 'create_user_failed');
  return u.id;
}
async function upsertLink(env, tgId, userId, username) {
  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/tg_links`, {
    method: 'POST', headers: { ...sbHeaders(env), Prefer: 'resolution=merge-duplicates' },
    body: JSON.stringify({ telegram_id: tgId, user_id: userId, username })
  });
  if (!r.ok) throw new Error('link_failed_' + r.status);
}
async function magicToken(env, email) {
  const r = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/generate_link`, {
    method: 'POST', headers: sbHeaders(env),
    body: JSON.stringify({ type: 'magiclink', email })
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.msg || d.message || 'generate_link_failed');
  return d.hashed_token || (d.properties && d.properties.hashed_token) || null;
}
async function userIdFromToken(env, accessToken) {
  const r = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, { headers: { apikey: env.SUPABASE_SERVICE_ROLE, authorization: `Bearer ${accessToken}` } });
  if (!r.ok) return null;
  const u = await r.json(); return u.id || null;
}
async function adminGetUser(env, userId) {
  const r = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users/${userId}`, { headers: sbHeaders(env) });
  if (!r.ok) return null; return r.json();
}
async function adminUpdateUser(env, userId, patch) {
  const r = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users/${userId}`, { method: 'PUT', headers: sbHeaders(env), body: JSON.stringify(patch) });
  const d = await r.json();
  if (!r.ok) throw new Error(d.msg || d.message || 'update_failed');
  return d;
}
async function patchReviewsUsername(env, userId, username) {
  await fetch(`${env.SUPABASE_URL}/rest/v1/reviews?user_id=eq.${userId}`, {
    method: 'PATCH', headers: { ...sbHeaders(env), Prefer: 'return=minimal' }, body: JSON.stringify({ username })
  });
}

// анти-перебор пароля для /account-claim: после RL_MAX неудач с одного IP —
// временная блокировка на RL_WINDOW_MIN минут. Счётчик в таблице rl_claim.
// ponytail: ключ по IP (CF-Connecting-IP), best-effort; хватает против перебора.
const RL_MAX = 10, RL_WINDOW_MIN = 15;
async function rlGet(env, ip) {
  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/rl_claim?ip=eq.${encodeURIComponent(ip)}&select=fails,until`, { headers: sbHeaders(env) });
  const a = await r.json().catch(() => null);
  return Array.isArray(a) && a[0] ? a[0] : null;
}
function rlBlocked(rl) { return !!(rl && rl.until && new Date(rl.until) > new Date()); }
async function rlFail(env, ip) {
  const cur = await rlGet(env, ip);
  const fails = ((cur && cur.fails) || 0) + 1;
  const until = fails >= RL_MAX ? new Date(Date.now() + RL_WINDOW_MIN * 60000).toISOString() : null;
  await fetch(`${env.SUPABASE_URL}/rest/v1/rl_claim`, {
    method: 'POST', headers: { ...sbHeaders(env), Prefer: 'resolution=merge-duplicates' },
    body: JSON.stringify({ ip, fails, until })
  });
}
async function rlReset(env, ip) {
  await fetch(`${env.SUPABASE_URL}/rest/v1/rl_claim?ip=eq.${encodeURIComponent(ip)}`, { method: 'DELETE', headers: sbHeaders(env) });
}

// смена имени профиля: имя в metadata + логин-почта + во всех обзорах автора
async function handleRename(request, env) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  if (!originOk(request)) return json({ error: 'bad_origin' }, 403);
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE) return json({ error: 'server_not_configured' }, 500);
  let body; try { body = await request.json(); } catch { return json({ error: 'bad_json' }, 400); }
  const newName = String(body.newUsername || '').toLowerCase().trim();
  if (!/^[a-zа-яё0-9_]{3,20}$/u.test(newName)) return json({ error: 'bad_name' }, 400);
  const slug = ruSlug(newName);
  if (slug.length < 2) return json({ error: 'bad_name' }, 400);
  if (!body.accessToken) return json({ error: 'no_session' }, 401);
  const userId = await userIdFromToken(env, body.accessToken);
  if (!userId) return json({ error: 'invalid_session' }, 401);
  try {
    const u = await adminGetUser(env, userId);
    if (!u) return json({ error: 'no_user' }, 404);
    const meta = { ...(u.user_metadata || {}), username: newName };
    try {
      await adminUpdateUser(env, userId, { email: slug + LOGIN_DOMAIN, email_confirm: true, user_metadata: meta });
    } catch (e) {
      if (/registered|exists|duplicate|already/i.test(String(e.message))) return json({ error: 'name_taken' }, 409);
      throw e;
    }
    await patchReviewsUsername(env, userId, newName);
    return json({ ok: true, username: newName });
  } catch (e) {
    return json({ error: String(e.message || e) }, 500);
  }
}

// перенос на существующий аккаунт: пользователь застрял в авто-аккаунте (вошёл
// через Telegram до привязки). По логину+паролю старого аккаунта переносим на
// него Telegram-привязку и обзоры авто-аккаунта, удаляем авто-аккаунт, логиним в старый.
async function handleClaim(request, env) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  if (!originOk(request)) return json({ error: 'bad_origin' }, 403);
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE) return json({ error: 'server_not_configured' }, 500);
  let body; try { body = await request.json(); } catch { return json({ error: 'bad_json' }, 400); }
  if (!body.accessToken) return json({ error: 'no_session' }, 401);
  const curId = await userIdFromToken(env, body.accessToken);
  if (!curId) return json({ error: 'invalid_session' }, 401);
  const slug = ruSlug(body.loginName || '');
  const password = String(body.password || '');
  if (slug.length < 2 || !password) return json({ error: 'bad_credentials' }, 400);
  const email = slug + LOGIN_DOMAIN;
  // анти-перебор: если с этого IP уже было 10 неудач — временно отказываем
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (rlBlocked(await rlGet(env, ip))) return json({ error: 'too_many_attempts' }, 429);
  try {
    // проверяем пароль старого аккаунта
    const tr = await fetch(`${env.SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method: 'POST', headers: { apikey: env.SUPABASE_SERVICE_ROLE, 'content-type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const td = await tr.json().catch(() => ({}));
    if (!tr.ok || !td.user) { await rlFail(env, ip); return json({ error: 'bad_credentials' }, 401); }
    await rlReset(env, ip);   // верный пароль — сбрасываем счётчик неудач
    const mainId = td.user.id;
    const mainName = (td.user.user_metadata && td.user.user_metadata.username) || slug;
    if (mainId !== curId) {
      // Telegram-привязки авто-аккаунта → на старый
      const lr = await fetch(`${env.SUPABASE_URL}/rest/v1/tg_links?user_id=eq.${curId}&select=telegram_id`, { headers: sbHeaders(env) });
      const links = await lr.json().catch(() => []);
      for (const l of (Array.isArray(links) ? links : [])) {
        await fetch(`${env.SUPABASE_URL}/rest/v1/tg_links?telegram_id=eq.${l.telegram_id}`, {
          method: 'PATCH', headers: { ...sbHeaders(env), Prefer: 'return=minimal' }, body: JSON.stringify({ user_id: mainId })
        });
      }
      // обзоры авто-аккаунта (если были) → на старый
      await fetch(`${env.SUPABASE_URL}/rest/v1/reviews?user_id=eq.${curId}`, {
        method: 'PATCH', headers: { ...sbHeaders(env), Prefer: 'return=minimal' }, body: JSON.stringify({ user_id: mainId, username: mainName })
      });
      // удаляем осиротевший авто-аккаунт: был привязан к Telegram (мы только что
      // увели его привязку) или почта телеграмная. Обзоры уже перевешены на старый.
      const hadLink = Array.isArray(links) && links.length > 0;
      const cu = await adminGetUser(env, curId);
      if (cu && (hadLink || /@telegram\./.test(cu.email || ''))) {
        await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users/${curId}`, { method: 'DELETE', headers: sbHeaders(env) });
      }
    }
    const token_hash = await magicToken(env, email);
    if (!token_hash) return json({ error: 'no_token' }, 500);
    return json({ ok: true, email, token_hash, username: mainName });
  } catch (e) {
    return json({ error: String(e.message || e) }, 500);
  }
}

async function handleTelegramAuth(request, env) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  if (!originOk(request)) return json({ error: 'bad_origin' }, 403);
  if (!env.BOT_TOKEN || !env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE) return json({ error: 'server_not_configured' }, 500);
  let body; try { body = await request.json(); } catch { return json({ error: 'bad_json' }, 400); }

  let tgUser = null;
  if (body.initData) tgUser = await verifyInitData(body.initData, env.BOT_TOKEN);
  else if (body.widget) tgUser = await verifyWidget(body.widget, env.BOT_TOKEN);
  if (!tgUser || !tgUser.id) return json({ error: 'telegram_verify_failed' }, 401);

  const tgId = Number(tgUser.id);
  const uname = String(tgUser.username || ('tg' + tgId)).toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20) || ('tg' + tgId);

  try {
    if (body.action === 'link') {
      if (!body.accessToken) return json({ error: 'no_session' }, 401);
      const meId = await userIdFromToken(env, body.accessToken);
      if (!meId) return json({ error: 'invalid_session' }, 401);
      const existing = await findLink(env, tgId);
      if (existing && existing.user_id !== meId) return json({ error: 'tg_taken' }, 409);
      await upsertLink(env, tgId, meId, uname);
      return json({ ok: true, linked: true, username: uname });
    }

    // action: login (по умолчанию)
    let link = await findLink(env, tgId);
    let userId, email;
    if (link) { userId = link.user_id; email = await getUserEmail(env, userId); }
    if (!email) {
      email = `tg${tgId}@${TG_EMAIL_DOMAIN}`;
      if (!link) { userId = await createUser(env, email, uname); await upsertLink(env, tgId, userId, uname); }
    }
    const token_hash = await magicToken(env, email);
    if (!token_hash) return json({ error: 'no_token' }, 500);
    return json({ ok: true, email, token_hash, username: uname });
  } catch (e) {
    return json({ error: String(e.message || e) }, 500);
  }
}
