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

const DELAY_MIN_MS = 30_000;
const DELAY_MAX_MS = 120_000;
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

// ── Twitter OAuth: Step 1 – GET sessions (dapat refresh_token) ───────────────
async function privyGetSession(privyToken) {
  const r = await fetch(`${AUTH_URL}/api/v1/sessions`, {
    method : "POST",
    headers: buildHeaders({
      "Authorization"           : `Bearer ${privyToken}`,
      "Referer"                 : `${BASE_URL}/`,
      "Sec-Fetch-Site"          : "cross-site",
      "Sec-Fetch-Storage-Access": "active",
      "Privy-App-Id"            : PRIVY_APP_ID,
      "Privy-Ca-Id"             : "77d9238a-53d3-4b00-90bd-9907ca3d839e",
      "Privy-Client"            : "react-auth:3.5.1",
    }),
    body: JSON.stringify({ refresh_token: null }),
  });
  if (!r.ok) throw new Error(`sessions HTTP ${r.status}: ${await r.text()}`);
  const data = await r.json();
  return data; // { token, refresh_token, ... }
}

// ── Step 4: Share / open task ─────────────────────────────────────────────────
async function earlyAccessShare(bearerToken) {
  const r = await fetch(`${BASE_URL}/api/early-access/share`, {
    method : "POST",
    headers: buildHeaders({
      "Authorization" : `Bearer ${bearerToken}`,
      "Referer"       : `${BASE_URL}/`,
      "Sec-Fetch-Site": "same-origin",
    }),
    body: JSON.stringify({}),
  });
  if (!r.ok) throw new Error(`share HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

// ── Post tweet share ─────────────────────────────────────────────────────────
const SHARE_TWEET = `I have registered to become an active participant in the emergence of a new autonomous network economy.\n\nI believe in forever.\nhttps://x.com/forevercultfund/status/2111124183082287549`;

async function postTweet(authToken, ct0) {
  const TWITTER_BEARER = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";
  const r = await fetch(`${TWITTER_API}/graphql/a1p9RWpkYKBjWv_I3WzS-A/CreateTweet`, {
    method : "POST",
    headers: {
      "Content-Type"             : "application/json",
      "Authorization"            : `Bearer ${TWITTER_BEARER}`,
      "X-Csrf-Token"             : ct0,
      "X-Twitter-Auth-Type"      : "OAuth2Session",
      "X-Twitter-Client-Language": "id",
      "Cookie"                   : `auth_token=${authToken}; ct0=${ct0}`,
      "User-Agent"               : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      "Origin"                   : "https://x.com",
      "Referer"                  : "https://x.com/",
    },
    body: JSON.stringify({
      variables: {
        tweet_text            : SHARE_TWEET,
        dark_request          : false,
        media                 : { media_entities: [], possibly_sensitive: false },
        semantic_annotation_ids: [],
      },
      features: {
        tweetypie_unmention_optimization_enabled                          : true,
        responsive_web_edit_tweet_api_enabled                             : true,
        responsive_web_graphql_exclude_directive_enabled                  : true,
        verified_phone_label_enabled                                      : false,
        creator_subscriptions_tweet_preview_api_enabled                   : true,
        responsive_web_graphql_timeline_navigation_enabled                : true,
        responsive_web_graphql_skip_user_profile_image_extensions_enabled : false,
        freedom_of_speech_not_reach_fetch_enabled                         : true,
        standardized_nudges_misinfo                                       : true,
        tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled: true,
        longform_notetweets_production_enabled                            : true,
        longform_notetweets_rich_text_read_enabled                        : true,
        longform_notetweets_inline_media_enabled                          : true,
        responsive_web_enhance_cards_enabled                              : false,
      },
    }),
  });
  const text = await r.text();
  log(`[postTweet] status: ${r.status}, body: ${text.slice(0, 500)}`);
  if (!r.ok) throw new Error(`postTweet HTTP ${r.status}: ${text}`);
  const json = JSON.parse(text);
  // GraphQL path: data.create_tweet.tweet_results.result.rest_id
  const tweetId = json?.data?.create_tweet?.tweet_results?.result?.rest_id;
  return { data: { id: tweetId }, raw: json };
}

// ── Twitter OAuth: Step 0 – Register OAuth flow dengan Privy ─────────────────
async function privyOAuthInit(privyToken, codeChallenge, stateCode) {
  const r = await fetch(`${AUTH_URL}/api/v1/oauth/init`, {
    method : "POST",
    headers: buildHeaders({
      "Authorization"           : `Bearer ${privyToken}`,
      "Referer"                 : `${BASE_URL}/`,
      "Sec-Fetch-Site"          : "cross-site",
      "Sec-Fetch-Storage-Access": "active",
      "Privy-App-Id"            : PRIVY_APP_ID,
      "Privy-Ca-Id"             : "77d9238a-53d3-4b00-90bd-9907ca3d839e",
      "Privy-Client"            : "react-auth:3.5.1",
    }),
    body: JSON.stringify({
      provider              : "twitter",
      code_challenge        : codeChallenge,
      code_challenge_method : "S256",
      state_code            : stateCode,
      redirect_to           : `${AUTH_URL}/api/v1/oauth/callback`,
    }),
  });
  if (!r.ok) throw new Error(`oauthInit HTTP ${r.status}: ${await r.text()}`);
  return r.json(); // { url: "https://x.com/i/oauth2/authorize?...&state=...&code_challenge=..." }
}

// ── Twitter OAuth: Step 2 – Get auth_code via X API JSON endpoint ─────────────
async function twitterGetAuthCode(authToken, ct0, state, codeChallenge) {
  const CLIENT_ID    = "YlJMT0QtbzB1RU1kaDd6Q2xPem06MTpjaQ";
  const REDIRECT_URI = `${AUTH_URL}/api/v1/oauth/callback`;
  const TWITTER_BEARER = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

  // Params untuk authorize
  const params = new URLSearchParams({
    response_type         : "code",
    client_id             : CLIENT_ID,
    redirect_uri          : REDIRECT_URI,
    scope                 : "users.read tweet.read",
    state                 : state,
    code_challenge        : codeChallenge,
    code_challenge_method : "S256",
  });

  // X punya endpoint JSON: GET /2/oauth2/authorize?... dengan Accept: application/json
  const r = await fetch(`${TWITTER_API}/2/oauth2/authorize?${params.toString()}`, {
    method : "GET",
    headers: {
      "User-Agent"           : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      "Accept"               : "application/json",
      "Accept-Language"      : "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
      "Authorization"        : `Bearer ${TWITTER_BEARER}`,
      "X-Csrf-Token"         : ct0,
      "X-Twitter-Auth-Type"  : "OAuth2Session",
      "X-Twitter-Client-Language": "id",
      "Cookie"               : `auth_token=${authToken}; ct0=${ct0}`,
      "Referer"              : "https://x.com/",
      "Sec-Fetch-Dest"       : "empty",
      "Sec-Fetch-Mode"       : "cors",
      "Sec-Fetch-Site"       : "same-site",
    },
  });

  const text = await r.text();
  log(`[twitterGetAuthCode] status: ${r.status}, body: ${text.slice(0, 200)}`);

  // Response JSON berisi { auth_code: "..." } atau { code: "..." }
  let formCode;
  try {
    const json = JSON.parse(text);
    formCode = json.auth_code || json.code || json.authCode;
    // Kalau sudah auto-approved, langsung dapat authorization_code
    if (json.redirect_uri) {
      const ru = new URL(json.redirect_uri);
      const ac = ru.searchParams.get("code");
      if (ac) return { authorizationCode: ac, callbackUrl: json.redirect_uri, state: ru.searchParams.get("state") || state, alreadyApproved: true };
    }
  } catch {}

  if (!formCode) throw new Error(`Gagal dapat auth_code dari X API. Status: ${r.status}, Body: ${text.slice(0, 300)}`);

  return { formCode, state, CLIENT_ID, REDIRECT_URI };
}

// ── Twitter OAuth: Step 3 – POST approval ke X ────────────────────────────────
async function twitterApprove(authToken, ct0, state, codeChallenge) {
  const { formCode, authorizationCode, callbackUrl, alreadyApproved } = await twitterGetAuthCode(authToken, ct0, state, codeChallenge);

  if (alreadyApproved) return { authorizationCode, callbackUrl, state };

  const TWITTER_BEARER = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

  const body = new URLSearchParams({
    approval     : "true",
    code         : formCode,   // auth_code dari GET → jadi form "code" di POST
    consent_flow : "web_consent",
  });

  const r = await fetch(`${TWITTER_API}/2/oauth2/authorize`, {
    method : "POST",
    headers: {
      "User-Agent"               : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      "Accept"                   : "application/json",
      "Accept-Language"          : "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
      "Content-Type"             : "application/x-www-form-urlencoded",
      "Authorization"            : `Bearer ${TWITTER_BEARER}`,
      "X-Csrf-Token"             : ct0,
      "X-Twitter-Auth-Type"      : "OAuth2Session",
      "X-Twitter-Client-Language": "id",
      "Cookie"                   : `auth_token=${authToken}; ct0=${ct0}`,
      "Origin"                   : "https://x.com",
      "Referer"                  : "https://x.com/",
      "Sec-Fetch-Dest"           : "empty",
      "Sec-Fetch-Mode"           : "cors",
      "Sec-Fetch-Site"           : "same-site",
    },
    body    : body.toString(),
    redirect: "manual",
  });

  const text = await r.text();
  log(`[twitterApprove] status: ${r.status}, body: ${text.slice(0, 300)}`);

  // Cek Location header (redirect ke privy callback)
  const location = r.headers.get("location");
  if (location) {
    const locUrl = new URL(location);
    const code   = locUrl.searchParams.get("code");
    if (code) return { authorizationCode: code, callbackUrl: location, state: locUrl.searchParams.get("state") || state };
  }

  // Parse JSON response — X return { redirect_uri: "...?code=...&state=..." }
  try {
    const json = JSON.parse(text);
    if (json.redirect_uri) {
      const ru   = new URL(json.redirect_uri);
      const code = ru.searchParams.get("code");
      if (code) return { authorizationCode: code, callbackUrl: json.redirect_uri, state: ru.searchParams.get("state") || state };
    }
  } catch {}

  throw new Error(`twitterApprove gagal. Status: ${r.status}, Body: ${text.slice(0, 300)}`);
}

// ── Twitter OAuth: Step 4 – POST /api/v1/oauth/link ke Privy ─────────────────
async function privyOAuthLink(authorizationCode, codeVerifier, stateCode, privyToken) {
  const r = await fetch(`${AUTH_URL}/api/v1/oauth/link`, {
    method : "POST",
    headers: buildHeaders({
      "Authorization"           : `Bearer ${privyToken}`,
      "Referer"                 : `${BASE_URL}/`,
      "Sec-Fetch-Site"          : "cross-site",
      "Sec-Fetch-Storage-Access": "active",
      "Privy-App-Id"            : PRIVY_APP_ID,
      "Privy-Ca-Id"             : "77d9238a-53d3-4b00-90bd-9907ca3d839e",
      "Privy-Client"            : "react-auth:3.5.1",
    }),
    body: JSON.stringify({
      authorization_code : authorizationCode,
      code_verifier      : codeVerifier,
      state_code         : stateCode,
    }),
  });
  if (!r.ok) throw new Error(`oauthLink HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

// ── Twitter OAuth: Step 4b – hit Privy callback langsung (Privy handle exchange) ─
async function privyOAuthCallback(callbackUrl, privyToken) {
  const r = await fetch(callbackUrl, {
    method  : "GET",
    headers : {
      "User-Agent"   : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      "Accept"       : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Authorization": `Bearer ${privyToken}`,
      "Privy-App-Id" : PRIVY_APP_ID,
      "Privy-Ca-Id"  : "77d9238a-53d3-4b00-90bd-9907ca3d839e",
      "Privy-Client" : "react-auth:3.5.1",
      "Referer"      : "https://x.com/",
    },
    redirect: "manual",
  });
  const text = await r.text();
  log(`[oauthCallback] status: ${r.status}, body: ${text.slice(0, 200)}`);
  if (r.status >= 400) throw new Error(`oauthCallback HTTP ${r.status}: ${text}`);

  // Privy return 307 → extract privy_oauth_code dari redirect URL
  const location = r.headers.get("location");
  if (location) {
    log(`[oauthCallback] redirect → ${location.slice(0, 200)}`);
    const locUrl        = new URL(location);
    const privyOAuthCode = locUrl.searchParams.get("privy_oauth_code");
    if (privyOAuthCode) return { privyOAuthCode };
  }

  throw new Error(`oauthCallback: privy_oauth_code tidak ditemukan (status ${r.status})`);
}

// ── Link Twitter to wallet account ───────────────────────────────────────────
async function linkTwitter(index, privyToken, twitterAccount) {
  const { auth_token, ct0 } = twitterAccount;

  log(`[${index + 1}] 🐦  Link Twitter dimulai...`);

  // 0. Init: kirim PKCE kita ke Privy
  const ourVerifier   = generateCodeVerifier();
  const ourChallenge  = generateCodeChallenge(ourVerifier);
  const ourState      = crypto.randomBytes(32).toString("base64url");

  const initData = await privyOAuthInit(privyToken, ourChallenge, ourState);
  log(`[${index + 1}] ✅  OAuth init OK`);

  // Privy generate state + code_challenge sendiri → ambil dari URL-nya
  const privyUrl      = new URL(initData.url);
  const state         = privyUrl.searchParams.get("state");
  const codeChallenge = privyUrl.searchParams.get("code_challenge");

  // 1. Twitter approve → dapat authorization_code + callbackUrl
  const { authorizationCode, callbackUrl } = await twitterApprove(auth_token, ct0, state, codeChallenge);
  log(`[${index + 1}] ✅  Twitter approved, code: ${authorizationCode.slice(0, 20)}…`);

  // 2. Hit Privy callback → Privy exchange code server-side → dapat privy_oauth_code
  log(`[${index + 1}] 🔗  oauthCallback: ${callbackUrl.slice(0, 100)}…`);
  const { privyOAuthCode } = await privyOAuthCallback(callbackUrl, privyToken);
  log(`[${index + 1}] ✅  Got privy_oauth_code`);

  // 3. Finalize link dengan privy_oauth_code
  const linkData = await privyOAuthLink(privyOAuthCode, ourVerifier, ourState, privyToken);
  log(`[${index + 1}] ✅  Twitter linked: ${JSON.stringify(linkData).slice(0, 200)}`);

  return linkData;
}

// ── Per-wallet flow ───────────────────────────────────────────────────────────
async function processWallet(privkey, index, twitterAccount) {
  let wallet;
  try {
    wallet = new ethers.Wallet(privkey.startsWith("0x") ? privkey : "0x" + privkey);
  } catch {
    log(`[${index + 1}] ❌  Private key tidak valid, skip.`);
    return { status: "invalid_key" };
  }

  const addr = wallet.address;
  log(`[${index + 1}] 🔑  ${addr}`);

  try {
    // 1. SIWE Init
    const { nonce, expires_at } = await siweInit(addr);
    log(`[${index + 1}] ✅  Nonce: ${nonce}`);

    // 2. Sign
    const message   = buildSiweMessage(addr, nonce, expires_at);
    const signature = await wallet.signMessage(message);
    log(`[${index + 1}] ✅  Signed`);

    // 3. Authenticate → dapat token
    const authData = await siweAuthenticate(message, signature);
    const token    = authData.token || authData.privy_access_token;
    if (!token) throw new Error("Token tidak ditemukan");
    log(`[${index + 1}] ✅  Auth token OK`);

    // 4. Register wallet
    const regData = await earlyAccessRegister(addr, token);
    log(`[${index + 1}] ✅  Register: ${JSON.stringify(regData)}`);

    // 5. Link Twitter dulu
    if (twitterAccount) {
      try {
        await linkTwitter(index, token, twitterAccount);
      } catch (tErr) {
        log(`[${index + 1}] ⚠️  Twitter link gagal (wallet tetap terdaftar): ${tErr.message}`);
      }
    } else {
      log(`[${index + 1}] ⏭  Tidak ada akun Twitter, skip link.`);
    }

    // 6. Share task (simulate klik task)
    try {
      const shareData = await earlyAccessShare(token);
      log(`[${index + 1}] ✅  Share: ${JSON.stringify(shareData)}`);
    } catch (sErr) {
      log(`[${index + 1}] ⚠️  Share gagal: ${sErr.message}`);
    }

    return { status: "success", address: addr };
  } catch (err) {
    log(`[${index + 1}] ❌  Error: ${err.message}`);
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
  console.log("║  [1] 1 akun saja (pilih nomor)     ║");
  console.log("║  [2] Semua akun                    ║");
  console.log("║  [3] From X to End                 ║");
  console.log("╚════════════════════════════════════╝");

  const choice = (await q("Pilih mode [1/2/3]: ")).trim();
  let start = 0, end = total - 1;

  if (choice === "1") {
    const num = parseInt(await q(`Nomor akun (1–${total}): `), 10);
    if (isNaN(num) || num < 1 || num > total) { console.error("Nomor tidak valid."); process.exit(1); }
    start = end = num - 1;
  } else if (choice === "2") {
    // semua
  } else if (choice === "3") {
    const from = parseInt(await q(`Dari nomor akun (1–${total}): `), 10);
    if (isNaN(from) || from < 1 || from > total) { console.error("Nomor tidak valid."); process.exit(1); }
    start = from - 1;
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
    console.log(`⚠️   Jumlah Twitter < Wallet. Akun ${twitters.length + 1}–${total} skip Twitter.`);
  }

  const { start, end } = await promptMode(total);
  console.log(`\n▶  Proses akun ${start + 1}–${end + 1} (${end - start + 1} akun)\n`);

  const results = { success: 0, error: 0, skip: 0 };

  for (let i = start; i <= end; i++) {
    const twitter = twitters[i] || null;
    const res     = await processWallet(keys[i], i, twitter);
    if (res.status === "success")    results.success++;
    else if (res.status === "invalid_key") results.skip++;
    else results.error++;
    if (i < end) {
      const delay = Math.floor(Math.random() * (DELAY_MAX_MS - DELAY_MIN_MS + 1)) + DELAY_MIN_MS;
      log(`⏳  Jeda ${(delay / 1000).toFixed(0)}s sebelum akun berikutnya...`);
      await sleep(delay);
    }
  }

  console.log("\n═══════ SUMMARY ═══════");
  console.log(`✅  Sukses : ${results.success}`);
  console.log(`❌  Error  : ${results.error}`);
  console.log(`⏭  Skip   : ${results.skip}`);
  console.log(`📝  Log    : ${LOG_FILE}`);
})();
