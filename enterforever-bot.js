const { ethers } = require("ethers");
const fs = require("fs");
const readline = require("readline");

// ── Config ────────────────────────────────────────────────────────────────────
const WALLET_FILE  = "wallet.txt";
const PRIVY_APP_ID = "cmvaxy57z00sv0fl89ga7d7mx";
const PRIVY_CA_ID  = "62a3dfd7-7fd9-4e65-9855-3fb7d9cde3ef";
const BASE_URL     = "https://enterforever.com";
const AUTH_URL     = "https://auth.privy.io";

const DELAY_MS     = 2000;   // jeda antar akun (ms)
const LOG_FILE     = "enterforever-log.txt";

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
  return fs
    .readFileSync(WALLET_FILE, "utf8")
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith("#"));
}

function buildHeaders(extra = {}) {
  return {
    "Content-Type"   : "application/json",
    "Accept"         : "application/json",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "User-Agent"     : "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Sec-Ch-Ua"      : '"Mises";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    "Sec-Ch-Ua-Mobile"  : "?1",
    "Sec-Ch-Ua-Platform": '"Android"',
    "Sec-Fetch-Dest" : "empty",
    "Sec-Fetch-Mode" : "cors",
    "Origin"         : BASE_URL,
    ...extra,
  };
}

// ── SIWE message builder (EIP-4361) ──────────────────────────────────────────
function buildSiweMessage(address, nonce) {
  const now      = new Date();
  const exp      = new Date(now.getTime() + 10 * 60 * 1000); // +10 menit
  return [
    `${BASE_URL.replace("https://","")} wants you to sign in with your Ethereum account:`,
    `${address}`,
    ``,
    `By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.`,
    ``,
    `URI: ${BASE_URL}`,
    `Version: 1`,
    `Chain ID: 1`,
    `Nonce: ${nonce}`,
    `Issued At: ${now.toISOString()}`,
    `Expiration Time: ${exp.toISOString()}`,
    `Resources:`,
    ` - https://privy.io`,
  ].join("\n");
}

// ── Step 1: SIWE init ─────────────────────────────────────────────────────────
async function siweInit(address) {
  const r = await fetch(`${AUTH_URL}/api/v1/siwe/init`, {
    method : "POST",
    headers: buildHeaders({
      "Referer"             : `${BASE_URL}/`,
      "Sec-Fetch-Site"      : "cross-site",
      "Sec-Fetch-Storage-Access": "active",
      "Privy-App-Id"        : PRIVY_APP_ID,
      "Privy-Ca-Id"         : PRIVY_CA_ID,
      "Privy-Client"        : "react-auth:3.5.1",
    }),
    body: JSON.stringify({ address }),
  });
  if (!r.ok) throw new Error(`siweInit HTTP ${r.status}: ${await r.text()}`);
  return r.json(); // { nonce, address, expires_at }
}

// ── Step 2: SIWE authenticate ─────────────────────────────────────────────────
async function siweAuthenticate(message, signature) {
  const r = await fetch(`${AUTH_URL}/api/v1/siwe/authenticate`, {
    method : "POST",
    headers: buildHeaders({
      "Referer"             : `${BASE_URL}/`,
      "Sec-Fetch-Site"      : "cross-site",
      "Sec-Fetch-Storage-Access": "active",
      "Privy-App-Id"        : PRIVY_APP_ID,
      "Privy-Ca-Id"         : PRIVY_CA_ID,
      "Privy-Client"        : "react-auth:3.5.1",
    }),
    body: JSON.stringify({ message, mode: "login-or-sign-up", signature }),
  });
  if (!r.ok) throw new Error(`siweAuth HTTP ${r.status}: ${await r.text()}`);
  return r.json(); // { token, privy_access_token, ... }
}

// ── Step 3: Early-access register ─────────────────────────────────────────────
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

// ── Per-wallet flow ───────────────────────────────────────────────────────────
async function processWallet(privkey, index) {
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
    // 1. Init
    const { nonce } = await siweInit(addr);
    log(`[${index}] ✅  Nonce: ${nonce}`);

    // 2. Sign
    const message   = buildSiweMessage(addr, nonce);
    const signature = await wallet.signMessage(message);
    log(`[${index}] ✅  Signature: ${signature.slice(0, 20)}…`);

    // 3. Authenticate
    const authData  = await siweAuthenticate(message, signature);
    const token     = authData.token || authData.privy_access_token;
    if (!token) throw new Error("Token tidak ditemukan di response authenticate");
    log(`[${index}] ✅  Token: ${token.slice(0, 30)}…`);

    // 4. Register
    const regData = await earlyAccessRegister(addr, token);
    log(`[${index}] ✅  Register: ${JSON.stringify(regData)}`);

    return { status: "success", address: addr };
  } catch (err) {
    log(`[${index}] ❌  Error: ${err.message}`);
    return { status: "error", address: addr, error: err.message };
  }
}

// ── Menu / Mode selector ──────────────────────────────────────────────────────
async function promptMode(total) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const q  = (txt) => new Promise(r => rl.question(txt, r));

  console.log("\n╔══════════════════════════════════╗");
  console.log("║   EnterForever SIWE Bot          ║");
  console.log(`║   Wallet loaded: ${String(total).padEnd(14)}║`);
  console.log("╠══════════════════════════════════╣");
  console.log("║  [1] 1 akun saja (pilih index)   ║");
  console.log("║  [2] Semua akun                  ║");
  console.log("║  [3] From X to End               ║");
  console.log("╚══════════════════════════════════╝");

  const choice = (await q("Pilih mode [1/2/3]: ")).trim();
  let start = 0, end = total - 1;

  if (choice === "1") {
    const idx = parseInt(await q(`Masukkan index akun (0 – ${total - 1}): `), 10);
    if (isNaN(idx) || idx < 0 || idx >= total) { console.error("Index tidak valid."); process.exit(1); }
    start = end = idx;
  } else if (choice === "2") {
    // all
  } else if (choice === "3") {
    const from = parseInt(await q(`Dari index (0 – ${total - 1}): `), 10);
    if (isNaN(from) || from < 0 || from >= total) { console.error("Index tidak valid."); process.exit(1); }
    start = from;
    // end tetap total-1
  } else {
    console.error("Pilihan tidak valid."); process.exit(1);
  }

  rl.close();
  return { start, end };
}

// ── Main ──────────────────────────────────────────────────────────────────────
(async () => {
  const keys   = loadWallets();
  const total  = keys.length;
  console.log(`\n📂  ${total} wallet ditemukan di ${WALLET_FILE}`);

  const { start, end } = await promptMode(total);
  console.log(`\n▶  Proses wallet index ${start} – ${end} (${end - start + 1} akun)\n`);

  const results = { success: 0, error: 0, skip: 0 };

  for (let i = start; i <= end; i++) {
    const res = await processWallet(keys[i], i);
    if (res.status === "success") results.success++;
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
