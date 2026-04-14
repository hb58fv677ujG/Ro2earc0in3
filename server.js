// ═══════════════════════════════════════════════════════════════════
//  Rollercoin Cloud Farmer — server.js
//  Enter email + password once → server gets Bearer token auto.
//  Token auto-refreshes when expired. No manual copy needed.
// ═══════════════════════════════════════════════════════════════════

const express   = require('express');
const WebSocket = require('ws');
const fetch     = require('node-fetch');
const CryptoJS  = require('crypto-js');
const fs        = require('fs');
const path      = require('path');
const http      = require('http');

const app    = express();
const server = http.createServer(app);
const PORT   = process.env.PORT || 3000;

// ─── Files ────────────────────────────────────────────────────────
const CONFIG_FILE = path.join(__dirname, 'config.json');
const STATE_FILE  = path.join(__dirname, 'state.json');

function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
  catch {
    return {
      email: '', password: '',
      bearerToken: '', csrfToken: '', refreshToken: '',
      maxHours: 4, levelLimit: 5, isOn: false
    };
  }
}
function saveConfig(c) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(c, null, 2)); }

function loadState() {
  try {
    const d = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    if (d.savedDate !== new Date().toDateString()) { d.usedMs = 0; d.savedDate = new Date().toDateString(); }
    return d;
  } catch { return { usedMs: 0, savedDate: new Date().toDateString() }; }
}
function saveState() {
  state.usedMs = totalUsedMs();
  state.savedDate = new Date().toDateString();
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

let config = loadConfig();
let state  = loadState();

// ─── Runtime ──────────────────────────────────────────────────────
let running     = false;
let startedAt   = null;
let stopTimer   = null;
let currentWs   = null;
let userId      = null;
let logs        = [];
let tokenStatus = 'none'; // 'none' | 'logging_in' | 'ok' | 'failed'
let gameStats   = { played: 0, totalPower: 0, lastGame: null };

// ─── Time helpers ─────────────────────────────────────────────────
function totalUsedMs() { return (running && startedAt) ? state.usedMs + (Date.now() - startedAt) : state.usedMs; }
function limitMs()     { return config.maxHours * 3600 * 1000; }
function remainingMs() { return Math.max(0, limitMs() - totalUsedMs()); }
function isLimitHit()  { return totalUsedMs() >= limitMs(); }
function fmtMs(ms) {
  if (ms <= 0) return '0h 00m';
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s/3600)}h ${String(Math.floor((s%3600)/60)).padStart(2,'0')}m`;
}

// ─── Logging ──────────────────────────────────────────────────────
function log(msg, level = 'info') {
  const entry = { t: new Date().toLocaleTimeString(), msg: String(msg), level };
  logs.unshift(entry);
  if (logs.length > 200) logs.pop();
  const icon = { success:'✅', warn:'⚠️', error:'❌', info:'ℹ️' }[level] || 'ℹ️';
  console.log(`[${entry.t}] ${icon} ${msg}`);
}

// ─── AUTO LOGIN ───────────────────────────────────────────────────
// Logs in with email + password, saves Bearer + refresh tokens.
async function autoLogin() {
  if (!config.email || !config.password) {
    log('No email/password configured.', 'error');
    tokenStatus = 'failed';
    return false;
  }
  tokenStatus = 'logging_in';
  log(`🔑 Logging in as ${config.email}...`, 'info');
  try {
    const res = await fetch('https://rollercoin.com/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36',
        'referer': 'https://rollercoin.com/signin',
        'origin': 'https://rollercoin.com'
      },
      body: JSON.stringify({ email: config.email.trim(), password: config.password.trim() })
    });

    // Extract CSRF from response cookies if present
    const cookies = res.headers.raw()['set-cookie'] || [];
    for (const ck of cookies) {
      const m = ck.match(/x-csrf=([^;]+)/i);
      if (m) {
        try { config.csrfToken = JSON.parse(decodeURIComponent(m[1])).token || m[1]; }
        catch { config.csrfToken = m[1]; }
      }
    }

    const data = await res.json().catch(() => null);
    if (!data) { log('Login: response parse failed.', 'error'); tokenStatus = 'failed'; return false; }
    if (!res.ok || !data.success) {
      log(`Login failed: ${data?.message || data?.error || 'HTTP ' + res.status}`, 'error');
      tokenStatus = 'failed';
      return false;
    }

    const access  = data.data?.access_token  || data.data?.token  || '';
    const refresh = data.data?.refresh_token || '';
    if (!access) { log('Login ok but no access_token returned.', 'error'); tokenStatus = 'failed'; return false; }

    config.bearerToken  = access.startsWith('Bearer ') ? access : 'Bearer ' + access;
    config.refreshToken = refresh;
    saveConfig(config);
    tokenStatus = 'ok';
    log('✅ Login successful — token saved!', 'success');
    return true;
  } catch (e) {
    log('Login error: ' + e.message, 'error');
    tokenStatus = 'failed';
    return false;
  }
}

// ─── TOKEN REFRESH ────────────────────────────────────────────────
// Tries refresh_token first, falls back to full re-login.
async function ensureFreshToken() {
  if (config.refreshToken) {
    try {
      const res  = await fetch('https://rollercoin.com/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: config.refreshToken })
      });
      const data = await res.json().catch(() => null);
      if (data?.success && data?.data?.access_token) {
        const acc = data.data.access_token;
        config.bearerToken  = acc.startsWith('Bearer ') ? acc : 'Bearer ' + acc;
        if (data.data.refresh_token) config.refreshToken = data.data.refresh_token;
        saveConfig(config);
        tokenStatus = 'ok';
        log('🔁 Token refreshed automatically.', 'success');
        return true;
      }
    } catch (e) { log('Refresh attempt failed: ' + e.message, 'warn'); }
  }
  // Fall back to re-login
  log('Refresh failed — re-logging in...', 'warn');
  return await autoLogin();
}

// ─── Game data ────────────────────────────────────────────────────
const gameNames = {
  1:'Coin Click', 2:'Token Blaster', 3:'Flappy Rocket', 4:'Cryptonoid',
  5:'Coin Match', 6:'Crypto Hamster', 7:'2048 Coin', 8:'Coin Flip',
  9:'Dr. Hamster', 10:'Token Surfer', 11:'Lambo Rider', 12:'Hamster Climber',
  13:'Coin Fisher', 14:'Mission Hampossible', 15:'Crypto Hex'
};
const rewardTable = {
  1:{1:1200,2:1200,3:1200,4:1200,5:1440,6:1440,7:1440,8:1440,9:1680,10:1680},
  2:{1:6552,2:7224,3:7722,4:8400,5:8961,6:9540,7:10062,8:10647,9:11232,10:14040},
  3:{1:2376,2:2592,3:2730,4:2940,5:3150,6:3360,7:3570,8:3780,9:3990,10:4200},
  4:{1:6768,2:6912,3:7200,4:7488,5:7632,6:7920,7:10944,8:11136,9:11520,10:11712},
  5:{1:2160,2:2196,3:2232,4:2646,5:2688,6:2730,7:2772,8:2814,9:2856,10:3126},
  6:{1:6090,2:6492,3:6906,4:7332,5:7770,6:8226,7:8688,8:9168,9:9654,10:10152},
  7:{1:1008,2:1071,3:1134,4:1197,5:1260,6:1323,7:1386,8:1449,9:1512,10:1575},
  8:{1:1152,2:1152,3:1152,4:1536,5:1608,6:1608,7:1608,8:2010,9:2010,10:2010},
  9:{1:3012,2:3294,3:3558,4:3804,5:4026,6:4230,7:4410,8:4584,9:4734,10:4866},
  10:{1:3528,2:3822,3:4116,4:4410,5:4704,6:4998,7:5292,8:5586,9:5880,10:6174},
  11:{1:6528,2:6975,3:7425,4:7872,5:8319,6:8769,7:9216,8:9663,9:10113,10:10560},
  12:{1:2550,2:2970,3:3330,4:3720,5:4080,6:4470,7:4860,8:5250,9:5640,10:6000},
  13:{1:2550,2:2970,3:3330,4:3720,5:4080,6:4470,7:4860,8:5250,9:5640,10:6000},
  14:{1:7000,2:8000,3:9000,4:10000,5:11000,6:12000,7:13000,8:14000,9:15000,10:16000},
  15:{1:2550,2:2970,3:3330,4:3720,5:4080,6:4470,7:4860,8:5250,9:5640,10:6000}
};
const timeTable = {
  13:{1:40,2:35,3:35,4:30,5:25,6:25,7:25,8:25,9:25,10:25},
  14:{1:45,2:45,3:40,4:40,5:35,6:35,7:30,8:30,9:25,10:25},
  15:{1:30,2:34,3:38,4:42,5:46,6:50,7:54,8:58,9:62,10:70}
};
function getReward(g,l)  { const t=rewardTable[String(g)]; return t?(t[String(l)]||0):0; }
function getTimeSec(g,l) { const t=timeTable[String(g)];   return t?(t[String(l)]||60):60; }

// ─── Encryption ───────────────────────────────────────────────────
const IV_STR = 'dYQ9R99bkKLsLHad';
function generateConstructed(uid) {
  const digits = [...uid].filter(c=>/\d/.test(c)).map(Number);
  const s = digits.reduce((a,b)=>a+b,0);
  return [...[...digits].sort((a,b)=>a-b), ...uid.slice(0,digits.length), s].join('');
}
function encryptData(text, uid) {
  const key = CryptoJS.enc.Utf8.parse(CryptoJS.MD5(generateConstructed(uid)).toString());
  const iv  = CryptoJS.enc.Utf8.parse(IV_STR);
  return CryptoJS.AES.encrypt(text, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString();
}

// ─── API fetch ────────────────────────────────────────────────────
async function apiFetch(url, opts={}) {
  const bearer = config.bearerToken.trim();
  const csrf   = config.csrfToken.trim();
  const headers = {
    'Content-Type': 'application/json', 'Accept': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36',
    'referer': 'https://rollercoin.com/',
    ...(bearer ? { 'Authorization': bearer.startsWith('Bearer ') ? bearer : 'Bearer '+bearer } : {}),
    ...(csrf   ? { 'csrf-token': csrf } : {})
  };
  const fetchOpts = { method: opts.method||'GET', headers };
  if (opts.body) fetchOpts.body = JSON.stringify(opts.body);
  return fetch(url, fetchOpts);
}

// ─── Sleep ────────────────────────────────────────────────────────
function sleep(ms) {
  return new Promise(resolve => {
    const iv = setInterval(()=>{ if(!running){clearInterval(iv);resolve();} }, 200);
    setTimeout(()=>{ clearInterval(iv); resolve(); }, ms);
  });
}

// ─── Main game flow ───────────────────────────────────────────────
async function mainFlow() {
  if (!running) return null;

  // Ensure token is fresh before each round
  if (!config.bearerToken) {
    const ok = await autoLogin();
    if (!ok) return 'no-token';
  } else {
    await ensureFreshToken();
  }

  let exitReason = null;
  try {
    const token = config.bearerToken.replace(/^Bearer\s+/i,'').trim();
    log('🔌 Connecting WebSocket...', 'info');

    await new Promise((resolve) => {
      const ws = new WebSocket(`wss://ws.rollercoin.com/cmd?token=${token}`);
      currentWs = ws;

      ws.on('open', () => {
        if (!running) { ws.close(); resolve(); return; }
        log('✅ Connected.', 'success');
        ws.send(JSON.stringify({ cmd: 'profile_data' }));
      });

      ws.on('message', async (raw) => {
        if (!running) { ws.close(); resolve(); return; }
        let msg; try { msg = JSON.parse(raw); } catch { return; }

        switch (msg.cmd) {
          case 'profile': {
            userId = msg.cmdval.userid;
            log(`📘 User: ${userId}`, 'info');
            ws.send(JSON.stringify({ cmd: 'games_data_request' }));
            break;
          }
          case 'games_data_response': {
            const lv = config.levelLimit || 5;
            const available = (msg.cmdval || []).filter(g => {
              const n = parseInt((g.level && (g.level.level||g.level))||0, 10);
              return n && n <= lv && g.cool_down === 0;
            });
            log(`🎮 Available games: ${available.length}`, 'info');
            if (!available.length) { exitReason='no-games'; ws.close(); resolve(); return; }

            const chosen  = available[Math.floor(Math.random()*available.length)];
            const gameNum = chosen.game_number;
            const lvlNum  = parseInt((chosen.level&&(chosen.level.level||chosen.level))||1, 10);
            log(`🎯 ${gameNames[gameNum]||'Game #'+gameNum} lv${lvlNum}`, 'success');

            const encStart = encryptData(JSON.stringify({game_number:gameNum}), userId);
            const rs = await apiFetch(`https://rollercoin.com/api/game/encode-start-game-data/${userId}?seccode=`,{method:'POST',body:{data:encStart}});
            const js = await rs.json();
            if (!js.success) { log('❌ Start failed.','error'); ws.close(); resolve(); return; }
            ws.send(JSON.stringify({cmd:'game_start_request',cmdval:js.data}));
            break;
          }
          case 'game_start_response': {
            const info    = msg.cmdval;
            const gameNum = info.game_number;
            const lvlNum  = info.level?.level || 1;
            const reward  = getReward(gameNum, lvlNum);
            const playSec = Math.max(1, getTimeSec(gameNum,lvlNum) - 2 - Math.floor(Math.random()*4));
            gameStats.lastGame = gameNames[gameNum] || 'Game #'+gameNum;
            log(`▶ Playing ${gameStats.lastGame} for ${playSec}s`, 'info');

            await sleep(playSec * 1000);
            if (!running) { ws.close(); resolve(); return; }

            const endObj = {power:reward, time:Date.now(), user_game_id:info.user_game_id, win_status:3};
            const encEnd = encryptData(JSON.stringify(endObj), userId);
            const re = await apiFetch(`https://rollercoin.com/api/game/encode-data/${userId}`,{method:'POST',body:{data:encEnd}});
            const je = await re.json();
            if (!je.success) { log('❌ End failed.','error'); ws.close(); resolve(); return; }
            ws.send(JSON.stringify({cmd:'game_end_request',cmdval:je.data}));
            break;
          }
          case 'game_finished_accepted': {
            gameStats.played++;
            gameStats.totalPower += msg.cmdval.power || 0;
            log(`🏁 +${msg.cmdval.power} power | Total: ${gameStats.totalPower}`, 'success');
            await sleep(3000);
            ws.close(); resolve();
            break;
          }
        }
      });

      ws.on('close', () => { currentWs=null; log('🔌 WebSocket closed.','warn'); resolve(); });
      ws.on('error', (e) => { log('WS error: '+e.message,'error'); resolve(); });
    });
  } catch(e) { log('mainFlow error: '+e.message,'error'); }
  return exitReason;
}

async function runLoop() {
  log('🚀 Automation started.','success');
  while (running && !isLimitHit()) {
    const r = await mainFlow();
    if (!running) break;
    if (r === 'no-token') { await stopAutomation('no-token'); break; }
    if (r === 'no-games') { log('⚠️ No games — waiting 5 min.','warn'); await sleep(5*60*1000); continue; }
    await sleep(2000);
  }
  if (isLimitHit()) { log(`⏹ ${config.maxHours}h daily limit hit!`,'warn'); await stopAutomation('limit'); }
}

async function startAutomation() {
  if (running) return;
  if (isLimitHit()) { log('Limit already hit. Resets midnight.','warn'); return; }
  if (!config.email && !config.bearerToken) { log('Set email+password first!','error'); return; }
  running=true; startedAt=Date.now(); config.isOn=true; saveConfig(config);
  if (stopTimer) clearTimeout(stopTimer);
  stopTimer = setTimeout(()=>stopAutomation('limit'), remainingMs());
  log(`▶ Limit: ${config.maxHours}h | Remaining: ${fmtMs(remainingMs())}`,'success');
  runLoop();
}

async function stopAutomation(reason) {
  state.usedMs=totalUsedMs(); running=false; startedAt=null; config.isOn=false; saveConfig(config);
  if (stopTimer) { clearTimeout(stopTimer); stopTimer=null; }
  try { if (currentWs) { currentWs.close(); currentWs=null; } } catch {}
  saveState();
  log(`■ Stopped (${reason}). Used: ${fmtMs(state.usedMs)}`,'warn');
}

function scheduleMidnightReset() {
  const now=new Date(), mid=new Date(now); mid.setHours(24,0,0,0);
  setTimeout(()=>{
    log('🌅 New day — counter reset!','info');
    state.usedMs=0; state.savedDate=new Date().toDateString(); saveState();
    gameStats.played=0; gameStats.totalPower=0;
    if (config.isOn && !running) startAutomation();
    scheduleMidnightReset();
  }, mid-now);
}

// ─── API ──────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

app.get('/api/status', (req,res) => {
  res.json({
    running, isOn:config.isOn, maxHours:config.maxHours, levelLimit:config.levelLimit,
    hasToken:!!config.bearerToken, hasLogin:!!(config.email&&config.password),
    email: config.email ? config.email.replace(/(.{2}).+(@.+)/,'$1***$2') : '',
    tokenStatus,
    usedFmt:fmtMs(totalUsedMs()), remFmt:fmtMs(remainingMs()),
    pct:Math.min(100,Math.round((totalUsedMs()/limitMs())*100)),
    limitHit:isLimitHit(), gameStats, logs:logs.slice(0,50)
  });
});

app.post('/api/toggle', async (req,res) => {
  if (req.body.on) await startAutomation(); else await stopAutomation('manual');
  res.json({ ok:true, running });
});

// Auto-login with email + password
app.post('/api/login', async (req,res) => {
  const { email, password } = req.body;
  if (!email||!password) return res.status(400).json({ok:false,error:'Email and password required'});
  config.email=email.trim(); config.password=password.trim();
  saveConfig(config);
  const ok = await autoLogin();
  res.json({ ok, tokenStatus, message: ok ? 'Logged in! Token saved.' : 'Login failed — check email/password.' });
});

app.post('/api/config', async (req,res) => {
  const {maxHours,levelLimit}=req.body;
  if (maxHours!=null)   config.maxHours  =Math.max(1,Math.min(24,Number(maxHours)));
  if (levelLimit!=null) config.levelLimit=Math.max(1,Math.min(10,Number(levelLimit)));
  saveConfig(config);
  if (running&&stopTimer) { clearTimeout(stopTimer); stopTimer=setTimeout(()=>stopAutomation('limit'),remainingMs()); }
  res.json({ok:true});
});

app.post('/api/reset', (req,res) => {
  state.usedMs=0; if(running) startedAt=Date.now(); saveState();
  if(config.isOn&&!running&&!isLimitHit()) startAutomation();
  res.json({ok:true});
});

server.listen(PORT, () => {
  console.log(`\n🚀 Rollercoin Cloud Farmer on port ${PORT}`);
  console.log(`   Open http://YOUR_SERVER_IP:${PORT} on your phone\n`);
  scheduleMidnightReset();
  if (config.email && config.password && !config.bearerToken) {
    autoLogin().then(ok => { if (ok && config.isOn && !isLimitHit()) startAutomation(); });
  } else if (config.isOn && config.bearerToken && !isLimitHit()) {
    startAutomation();
  }
});

process.on('SIGTERM', async()=>{ await stopAutomation('shutdown'); process.exit(0); });
process.on('SIGINT',  async()=>{ await stopAutomation('shutdown'); process.exit(0); });
