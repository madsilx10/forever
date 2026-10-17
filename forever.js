const { ethers } = require("ethers");
const fs = require("fs");
const readline = require("readline");
const crypto = require("crypto");

// ── Config ────────────────────────────────────────────────────────────────────
const WALLET_FILE  = "wallet.txt";
const TWITTER_FILE = "akun.txt";
const PRIVY_APP_ID = "cmvaxy57z00sv0fl89ga7d7mx";
const PRIVY_CA_ID  = "62a3dfd7-7fd9-4e65-9855-3fb7d9cde3ef";
const BASE_URL     = "https://enterforever.com";
const AUTH_URL     = "https://auth.privy.io";
const TWITTER_API  = "https://api.x.com";

const DELAY_MS     = 3000;
const LOG_FILE     = "forever-log.txt";

// ── Helpers ───────────────────────────────────────────────────────────────────
function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + "\n");
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function loadWallets() {
  if (!fs.existsSync(WALLET_FILE)) {
    console.error(`❌  File "${WALLET_FILE}" tidak ditemukan.`);
    process.exit(1);
  }
  return fs.readFileSync(WALLET_FILE, "utf8")
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith("#"));
}

function loadTwitterAccounts() {
  if (!fs.existsSync(TWITTER_FILE)) return [];
  const lines = fs.readFileSync(TWITTER_FILE, "utf8")
    .split("\n")
    .map(l => l.trim());

  const accounts = [];
  let i = 0;
  while (i < lines.length) {
    // skip baris kosong
    while (i < lines.length && lines[i] === "") i++;
    if (i >= lines.length) break;
    const auth_token = lines[i++];
    while (i < lines.length && lines[i] === "") { /* skip */ i++; break; }
    // ambil ct0 setelah auth_token (baris berikutnya non-kosong)
    // reset: cari ct0 = baris langsung setelah auth_token
    // format: authtoken \n ct0 \n \n authtoken2 \n ct0_2
    let ct0 = "";
    // i sudah maju karena while di atas break, cek lagi
    // lebih simpel: parse ulang per blok
    accounts.push({ auth_token, ct0 });
  }

  // Parse ulang lebih clean
  accounts.length = 0;
  const raw = fs.readFileSync(TWITTER_FILE, "utf8");
  const blocks = raw.split(/\n\s*\n/).map(b => b.trim()).filter(Boolean);
  for (const block of blocks) {
    const [auth_token, ct0] = block.split("\n").map(l => l.trim());
    if (auth_token && ct0) accounts.push({ auth_token, ct0 });
  }
  return accounts;
}

function buildHeaders(extra = {}) {
  return {
    "Content-Type"      : "application/json",
    "Accept"            : "application/json",
    "Accept-Language"   : "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "User-Agent"        : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Sec-Ch-Ua"         : '"Mises";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    "Sec-Ch-Ua-Mobile"  : "?1",
    "Sec-Ch-Ua-Platform": '"Android"',
    "Sec-Fetch-Dest"    : "empty",
    "Sec-Fetch-Mode"    : "cors",
    "Origin"            : BASE_URL,
    ...extra,
  };
}

// ── PKCE helpers ──────────────────────────────────────────────────────────────
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

// ── SIWE message builder ──────────────────────────────────────────────────────
function buildSiweMessage(address, nonce, expiresAt) {
  const now = new Date();
  return (
    `enterforever.com wants you to sign in with your Ethereum account:\n` +
    `${address}\n` +
    `\n` +
    `By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n` +
    `\n` +
    `URI: https://enterforever.com\n` +
    `Version: 1\n` +
    `Chain ID: 46630\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${now.toISOString()}\n` +
    `Expiration Time: ${expiresAt}\n` +
    `Resources:\n` +
    `- https://privy.io`
  );
}

// ── Step 1: SIWE init ─────────────────────────────────────────────────────────
async function siweInit(address) {
  const r = await fetch(`${AUTH_URL}/api/v1/siwe/init`, {
    method : "POST",
    headers: buildHeaders({
      "Referer"                 : `${BASE_URL}/`,
      "Sec-Fetch-Site"          : "cross-site",
      "Sec-Fetch-Storage-Access": "active",
      "Privy-App-Id"            : PRIVY_APP_ID,
      "Privy-Ca-Id"             : PRIVY_CA_ID,
      "Privy-Client"            : "react-auth:3.5.1",
    }),
    body: JSON.stringify({ address }),
  });
  if (!r.ok) throw new Error(`siweInit HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

// ── Step 2: SIWE authenticate ─────────────────────────────────────────────────
async function siweAuthenticate(message, signature) {
  const r = await fetch(`${AUTH_URL}/api/v1/siwe/authenticate`, {
    method : "POST",
    headers: buildHeaders({
      "Referer"                 : `${BASE_URL}/`,
      "Sec-Fetch-Site"          : "cross-site",
      "Sec-Fetch-Storage-Access": "active",
      "Privy-App-Id"            : PRIVY_APP_ID,
      "Privy-Ca-Id"             : PRIVY_CA_ID,
      "Privy-Client"            : "react-auth:3.5.1",
    }),
    body: JSON.stringify({ message, mode: "login-or-sign-up", signature }),
  });
  if (!r.ok) throw new Error(`siweAuth HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

// ── Step 3: Register wallet ───────────────────────────────────────────────────
async function earlyAccessRegister(walletAddress, bearerToken) {
  const r = await fetch(`${BASE_URL}/api/early-access/register`, {
    method : "POST",
    headers: buildHeaders({
      "Authorization" : `Bearer ${bearerToken}`,
      "Referer"       : `${BASE_URL}/`,
      "Sec-Fetch-Site": "same-origin",
    }),
    body: JSON.stringify({ wallet: walletAddress.toLowerCase(), consent: true }),
  });
  if (!r.ok) throw new Error(`register HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

// ── Twitter OAuth: Step 1 – privy oauth init ──────────────────────────────────
async function privyOAuthInit(privyToken) {
  const codeVerifier  = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  const r = await fetch(`${AUTH_URL}/api/v1/oauth/init`, {
    method : "POST",
    headers: buildHeaders({
      "Authorization"  : `Bearer ${privyToken}`,
      "Referer"        : `${BASE_URL}/`,
      "Sec-Fetch-Site" : "cross-site",
      "Privy-App-Id"   : PRIVY_APP_ID,
      "Privy-Ca-Id"    : PRIVY_CA_ID,
      "Privy-Client"   : "react-auth:3.5.1",
    }),
    body: JSON.stringify({
      provider         : "twitter",
      redirect_uri     : `${AUTH_URL}/api/v1/oauth/callback`,
      response_type    : "code",
      scope            : "users.read tweet.read",
      code_challenge   : codeChallenge,
      code_challenge_method: "S256",
    }),
  });
  if (!r.ok) throw new Error(`oauthInit HTTP ${r.status}: ${await r.text()}`);
  const data = await r.json();
  // data: { state, authorization_url, ... }
  return { ...data, codeVerifier, codeChallenge };
}

// ── Twitter OAuth: Step 2 – GET authorize page (dapat auth_code) ──────────────
async function twitterGetAuthCode(authorizationUrl, authToken, ct0) {
  // Parse params dari authorization_url
  const url    = new URL(authorizationUrl);
  const state  = url.searchParams.get("state");
  const clientId     = url.searchParams.get("client_id");
  const codeChallenge = url.searchParams.get("code_challenge");
  const redirectUri  = url.searchParams.get("redirect_uri");

  // GET halaman authorize di X
  const getR = await fetch(authorizationUrl, {
    method : "GET",
    headers: {
      "User-Agent"     : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      "Accept"         : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
      "Sec-Fetch-Dest" : "document",
      "Sec-Fetch-Mode" : "navigate",
      "Sec-Fetch-Site" : "cross-site",
      "Upgrade-Insecure-Requests": "1",
      "Cookie"         : `auth_token=${authToken}; ct0=${ct0}`,
      "Referer"        : "https://x.com/",
    },
    redirect: "manual",
  });

  // Ambil auth_code dari response body (ada di JSON viewer.json atau di HTML)
  // X akan redirect ke privy callback dengan code
  // Kalau status 200, parse auth_code dari HTML atau JSON
  const body = await getR.text();

  // Coba extract auth_code dari meta atau script
  // X OAuth2 approval page ada form dengan hidden "code"
  const codeMatch = body.match(/"authCode"\s*:\s*"([^"]+)"/);
  if (codeMatch) return codeMatch[1];

  // Alternatif: ambil dari Location header kalau redirect
  const location = getR.headers.get("location");
  if (location) {
    const locUrl  = new URL(location);
    const code    = locUrl.searchParams.get("code");
    if (code) return code;
  }

  throw new Error(`Gagal dapat auth_code dari Twitter. Status: ${getR.status}`);
}

// ── Twitter OAuth: Step 3 – POST approval ─────────────────────────────────────
async function twitterApprove(authorizationUrl, authToken, ct0) {
  const url      = new URL(authorizationUrl);
  const state    = url.searchParams.get("state");
  const clientId = url.searchParams.get("client_id");

  // POST approve
  const body = new URLSearchParams({
    approval      : "true",
    code          : await twitterGetAuthCodeFromApproval(authorizationUrl, authToken, ct0),
    consent_flow  : "web_consent",
  });

  const r = await fetch(`${TWITTER_API}/2/oauth2/authorize`, {
    method : "POST",
    headers: {
      "User-Agent"          : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      "Accept"              : "*/*",
      "Accept-Language"     : "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
      "Content-Type"        : "application/x-www-form-urlencoded",
      "Sec-Fetch-Dest"      : "empty",
      "Sec-Fetch-Mode"      : "cors",
      "Sec-Fetch-Site"      : "same-site",
      "Origin"              : "https://x.com",
      "Referer"             : "https://x.com/",
      "Authorization"       : `Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
      "X-Csrf-Token"        : ct0,
      "Cookie"              : `auth_token=${authToken}; ct0=${ct0}`,
      "X-Twitter-Auth-Type" : "OAuth2Session",
      "X-Twitter-Client-Language": "id",
    },
    body: body.toString(),
    redirect: "manual",
  });

  // Response berisi redirect ke privy callback dengan code
  const location = r.headers.get("location");
  if (location) {
    const locUrl = new URL(location);
    const code   = locUrl.searchParams.get("code");
    if (code) return { code, state: locUrl.searchParams.get("state") || state };
  }

  const respText = await r.text();
  // Coba parse JSON response (X kadang return JSON dengan redirect_uri)
  try {
    const json = JSON.parse(respText);
    if (json.redirect_uri) {
      const ru   = new URL(json.redirect_uri);
      const code = ru.searchParams.get("code");
      if (code) return { code, state: ru.searchParams.get("state") || state };
    }
  } catch {}

  throw new Error(`twitterApprove gagal. Status: ${r.status} Body: ${respText.slice(0, 200)}`);
}

// Ambil "code" token dari halaman GET authorize (form hidden input)
async function twitterGetAuthCodeFromApproval(authorizationUrl, authToken, ct0) {
  const r = await fetch(authorizationUrl, {
    method : "GET",
    headers: {
      "User-Agent"     : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      "Accept"         : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
      "Sec-Fetch-Dest" : "document",
      "Sec-Fetch-Mode" : "navigate",
      "Sec-Fetch-Site" : "cross-site",
      "Upgrade-Insecure-Requests": "1",
      "Cookie"         : `auth_token=${authToken}; ct0=${ct0}`,
      "Referer"        : "https://x.com/",
    },
    redirect: "follow",
  });

  const html = await r.text();

  // X menyimpan auth code di hidden input atau JSON dalam script
  // Pattern 1: <input name="code" value="...">
  const m1 = html.match(/name="code"\s+value="([^"]+)"/);
  if (m1) return m1[1];

  // Pattern 2: "code":"..."
  const m2 = html.match(/"code"\s*:\s*"([A-Za-z0-9_\-]{20,})"/);
  if (m2) return m2[1];

  // Pattern 3: value="..." di form (urutan berbeda)
  const m3 = html.match(/value="([A-Za-z0-9_\-]{40,})"/);
  if (m3) return m3[1];

  throw new Error(`Gagal extract code dari halaman Twitter authorize`);
}

// ── Twitter OAuth: Step 4 – privy oauth callback ──────────────────────────────
async function privyOAuthCallback(code, state, codeVerifier, privyToken) {
  const r = await fetch(`${AUTH_URL}/api/v1/oauth/callback`, {
    method : "POST",
    headers: buildHeaders({
      "Authorization" : `Bearer ${privyToken}`,
      "Referer"       : `${BASE_URL}/`,
      "Sec-Fetch-Site": "cross-site",
      "Privy-App-Id"  : PRIVY_APP_ID,
      "Privy-Ca-Id"   : PRIVY_CA_ID,
      "Privy-Client"  : "react-auth:3.5.1",
    }),
    body: JSON.stringify({
      provider      : "twitter",
      code,
      state,
      redirect_uri  : `${AUTH_URL}/api/v1/oauth/callback`,
      code_verifier : codeVerifier,
    }),
  });
  if (!r.ok) throw new Error(`oauthCallback HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

// ── Link Twitter to wallet account ───────────────────────────────────────────
async function linkTwitter(index, privyToken, twitterAccount) {
  const { auth_token, ct0 } = twitterAccount;

  log(`[${index}] 🐦  Link Twitter dimulai...`);

  // 1. Init OAuth di Privy
  const { state, authorization_url, codeVerifier } = await privyOAuthInit(privyToken);
  log(`[${index}] ✅  OAuth init OK, state: ${state.slice(0, 20)}…`);

  // 2. GET + POST approve di Twitter
  const { code } = await twitterApprove(authorization_url, auth_token, ct0);
  log(`[${index}] ✅  Twitter approved, code: ${code.slice(0, 20)}…`);

  // 3. Callback ke Privy
  const callbackData = await privyOAuthCallback(code, state, codeVerifier, privyToken);
  log(`[${index}] ✅  Twitter linked: ${JSON.stringify(callbackData).slice(0, 100)}`);

  return callbackData;
}

// ── Per-wallet flow ───────────────────────────────────────────────────────────
async function processWallet(privkey, index, twitterAccount) {
  let wallet;
  try {
    wallet = new ethers.Wallet(privkey.startsWith("0x") ? privkey : "0x" + privkey);
  } catch {
    log(`[${index}] ❌  Private key tidak valid, skip.`);
    return { status: "invalid_key" };
  }

  const addr = wallet.address;
  log(`[${index}] 🔑  ${addr}`);

  try {
    // 1. SIWE Init
    const { nonce, expires_at } = await siweInit(addr);
    log(`[${index}] ✅  Nonce: ${nonce}`);

    // 2. Sign
    const message   = buildSiweMessage(addr, nonce, expires_at);
    const signature = await wallet.signMessage(message);
    log(`[${index}] ✅  Signed`);

    // 3. Authenticate → dapat token
    const authData = await siweAuthenticate(message, signature);
    const token    = authData.token || authData.privy_access_token;
    if (!token) throw new Error("Token tidak ditemukan");
    log(`[${index}] ✅  Auth token OK`);

    // 4. Register wallet
    const regData = await earlyAccessRegister(addr, token);
    log(`[${index}] ✅  Register: ${JSON.stringify(regData)}`);

    // 5. Link Twitter (jika ada)
    if (twitterAccount) {
      try {
        await linkTwitter(index, token, twitterAccount);
      } catch (tErr) {
        log(`[${index}] ⚠️  Twitter gagal (wallet tetap terdaftar): ${tErr.message}`);
      }
    } else {
      log(`[${index}] ⏭  Tidak ada akun Twitter, skip link.`);
    }

    return { status: "success", address: addr };
  } catch (err) {
    log(`[${index}] ❌  Error: ${err.message}`);
    return { status: "error", address: addr, error: err.message };
  }
}

// ── Menu ──────────────────────────────────────────────────────────────────────
async function promptMode(total) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const q  = txt => new Promise(r => rl.question(txt, r));

  console.log("\n╔════════════════════════════════════╗");
  console.log("║   EnterForever Bot                 ║");
  console.log(`║   Wallet  : ${String(total).padEnd(22)}║`);
  console.log("╠════════════════════════════════════╣");
  console.log("║  [1] 1 akun saja (pilih index)     ║");
  console.log("║  [2] Semua akun                    ║");
  console.log("║  [3] From X to End                 ║");
  console.log("╚════════════════════════════════════╝");

  const choice = (await q("Pilih mode [1/2/3]: ")).trim();
  let start = 0, end = total - 1;

  if (choice === "1") {
    const idx = parseInt(await q(`Index akun (0–${total - 1}): `), 10);
    if (isNaN(idx) || idx < 0 || idx >= total) { console.error("Index tidak valid."); process.exit(1); }
    start = end = idx;
  } else if (choice === "2") {
    // semua
  } else if (choice === "3") {
    const from = parseInt(await q(`Dari index (0–${total - 1}): `), 10);
    if (isNaN(from) || from < 0 || from >= total) { console.error("Index tidak valid."); process.exit(1); }
    start = from;
  } else {
    console.error("Pilihan tidak valid."); process.exit(1);
  }

  rl.close();
  return { start, end };
}

// ── Main ──────────────────────────────────────────────────────────────────────
(async () => {
  const keys     = loadWallets();
  const twitters = loadTwitterAccounts();
  const total    = keys.length;

  console.log(`\n📂  Wallet   : ${total}`);
  console.log(`🐦  Twitter  : ${twitters.length}`);
  if (twitters.length > 0 && twitters.length < total) {
    console.log(`⚠️   Jumlah Twitter < Wallet. Akun index ${twitters.length}–${total-1} skip Twitter.`);
  }

  const { start, end } = await promptMode(total);
  console.log(`\n▶  Proses index ${start}–${end} (${end - start + 1} akun)\n`);

  const results = { success: 0, error: 0, skip: 0 };

  for (let i = start; i <= end; i++) {
    const twitter = twitters[i] || null;
    const res     = await processWallet(keys[i], i, twitter);
    if (res.status === "success")    results.success++;
    else if (res.status === "invalid_key") results.skip++;
    else results.error++;
    if (i < end) await sleep(DELAY_MS);
  }

  console.log("\n═══════ SUMMARY ═══════");
  console.log(`✅  Sukses : ${results.success}`);
  console.log(`❌  Error  : ${results.error}`);
  console.log(`⏭  Skip   : ${results.skip}`);
  console.log(`📝  Log    : ${LOG_FILE}`);
})();
