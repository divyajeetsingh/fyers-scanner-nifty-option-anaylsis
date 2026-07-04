// ============================================================
//  REAL-TIME OPTION CHAIN SCANNER (NODE.JS VERSION)
//  FAST + LOW API USAGE + CONCURRENT + WEB DASHBOARDS
// ============================================================

const fs = require('fs');
const path = require('path');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const axios = require('axios');
const { authenticator } = require('otplib');
const express = require('express');
const WebSocket = require('ws');
const { fyersModel, fyersDataSocket } = require('fyers-api-v3');

// ============================================================
// CONFIG & GLOBALS
// ============================================================

let credentials = {};
try {
    credentials = JSON.parse(fs.readFileSync(path.join(__dirname, 'credentials.json'), 'utf-8'));
} catch (e) {
    console.error("❌ Failed to read credentials.json.", e.message);
    process.exit(1);
}

const FY_ID = credentials.FY_ID;
const APP_ID = credentials.APP_ID;
const APP_TYPE = credentials.APP_TYPE;
const SECRET_KEY = credentials.SECRET_KEY;
const TOTP_KEY = credentials.TOTP_KEY;
const PIN = credentials.PIN;
const REDIRECT_URI = credentials.REDIRECT_URI;

// Scanner Configuration
const SYMBOL = "NSE:NIFTY50-INDEX";
const STEP = 100;
const STRIKE_RANGE = 3;
const REFRESH_INTERVAL = 3; // seconds for terminal refresh
const COOLDOWN = 20;
const SPIKE_MULTIPLIER = 1.5;

const MAX_RETRIES = 999;
const RETRY_DELAY = 5; // seconds

const WS_CHUNK_SIZE = 200;
const WS_CHUNK_DELAY = 0.5; // seconds
const WS_RECONNECT_DELAY = 10; // seconds

// State maps
const optionChain = {};
const alerted = {};
let symbols = [];
let strikes = [];
let currentAtm = 0;
let fullOptionChainMap = {};

let ACCESS_TOKEN = null;
let CLIENT_ID = null;
let fyers = null; // FyersModel REST instance
let fyersWs = null; // FyersDataSocket instance
let wsConnected = false;
let wsClosed = false;

let wss = null; // local WS broadcaster instance
const connectedClients = new Set();

// ============================================================
// LICENSE CHECK
// ============================================================

async function checkLicense() {
    try {
        const checkUrl = "https://gitsof.com/copyright.json";
        const response = await axios.get(checkUrl, {
            timeout: 10000,
            httpsAgent: new https.Agent({ rejectUnauthorized: false })
        });
        if (response.status !== 200) {
            console.error(`❌ License verification failed: Server returned status ${response.status}`);
            process.exit(1);
        }
        const data = response.data;
        const environments = data.environments || {};
        const allowedNames = new Set();
        for (const key in environments) {
            const env = environments[key];
            if (env && typeof env === 'object' && env.name) {
                allowedNames.add(env.name);
            }
        }
        
        const targetName = "divyajeetsinghfxinvestor";
        if (!allowedNames.has(targetName)) {
            console.error(`❌ License verification failed: '${targetName}' is not authorized.`);
            process.exit(1);
        }
        
        console.log("✅ License verified successfully.");
    } catch (e) {
        console.error(`❌ License verification error: ${e.message}`);
        process.exit(1);
    }
}

// ============================================================
// CREDENTIALS & SESSION COOKIES
// ============================================================

let sessionCookies = [];

async function fyersPost(postUrl, payload, extraHeaders = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...extraHeaders
    };
    if (sessionCookies.length > 0) {
        headers['Cookie'] = sessionCookies.join('; ');
    }

    const response = await axios.post(postUrl, payload, { 
        headers, 
        timeout: 15000,
        validateStatus: (status) => status >= 200 && status < 400 
    });

    const setCookie = response.headers['set-cookie'];
    if (setCookie) {
        for (const cookie of setCookie) {
            const cookiePart = cookie.split(';')[0];
            const cookieName = cookiePart.split('=')[0];
            const idx = sessionCookies.findIndex(c => c.startsWith(cookieName + '='));
            if (idx !== -1) {
                sessionCookies[idx] = cookiePart;
            } else {
                sessionCookies.push(cookiePart);
            }
        }
    }

    return response.data;
}

// ============================================================
// AUTOMATED FYERS LOGIN
// ============================================================

function loadCachedToken() {
    try {
        const cachePath = path.join(__dirname, 'access_token.json');
        if (fs.existsSync(cachePath)) {
            const data = JSON.parse(fs.readFileSync(cachePath, 'utf-8'));
            if (data && data.ACCESS_TOKEN && data.CLIENT_ID) {
                ACCESS_TOKEN = data.ACCESS_TOKEN;
                CLIENT_ID = data.CLIENT_ID;
                console.log("🔑 Successfully loaded cached token from access_token.json");
                return true;
            }
        }
    } catch (e) {
        console.warn("⚠️ Could not load cached token:", e.message);
    }
    return false;
}

function saveTokenToCache(token, clientId) {
    try {
        const cachePath = path.join(__dirname, 'access_token.json');
        fs.writeFileSync(cachePath, JSON.stringify({ ACCESS_TOKEN: token, CLIENT_ID: clientId }, null, 4));
        console.log("💾 Saved token to access_token.json");
    } catch (e) {
        console.warn("⚠️ Failed to write to access_token.json:", e.message);
    }
}

async function performLogin() {
    console.log("🚀 Starting automated Fyers programmatic authentication flow...");
    sessionCookies = [];

    // Step 1: Send Login OTP
    console.log("Step 1: Sending Login OTP request...");
    const r1 = await fyersPost("https://api-t2.fyers.in/vagator/v2/send_login_otp", {
        fy_id: FY_ID,
        app_id: "2"
    });

    if (r1.s !== "ok") {
        throw new Error(`Fyers send_login_otp failed: ${JSON.stringify(r1)}`);
    }
    let requestKey = r1.request_key;
    console.log("✅ Login OTP request successful.");

    // Step 2: Generate and Verify TOTP
    console.log("Step 2: Generating and verifying TOTP token...");
    authenticator.options = { digits: 6, step: 30 };
    const totp = authenticator.generate(TOTP_KEY);

    const r2 = await fyersPost("https://api-t2.fyers.in/vagator/v2/verify_otp", {
        request_key: requestKey,
        otp: totp
    });

    if (r2.s !== "ok") {
        throw new Error(`Fyers verify_otp failed: ${JSON.stringify(r2)}`);
    }
    requestKey = r2.request_key;
    console.log("✅ TOTP verification successful.");

    // Step 3: Verify security PIN
    console.log("Step 3: Verifying user security PIN...");
    const r3 = await fyersPost("https://api-t2.fyers.in/vagator/v2/verify_pin", {
        request_key: requestKey,
        identity_type: "pin",
        identifier: PIN
    });

    if (r3.s !== "ok") {
        throw new Error(`Fyers verify_pin failed: ${JSON.stringify(r3)}`);
    }
    const access_token_stage1 = r3.data.access_token;
    console.log("✅ PIN verification successful.");

    // Step 4: Generate authorization code (auth_code)
    console.log("Step 4: Requesting redirect URL to extract auth code...");
    const appIdWithoutType = APP_ID.replace("-100", "");
    const r4 = await fyersPost("https://api-t1.fyers.in/api/v3/token", {
        fyers_id: FY_ID,
        app_id: appIdWithoutType,
        redirect_uri: REDIRECT_URI,
        appType: APP_TYPE,
        code_challenge: "",
        state: "sample_state",
        scope: "",
        nonce: "",
        response_type: "code",
        create_cookie: true
    }, {
        Authorization: `Bearer ${access_token_stage1}`
    });

    if (r4.s !== "ok") {
        throw new Error(`Fyers auth code generation failed: ${JSON.stringify(r4)}`);
    }

    const redirectUrl = r4.Url;
    const parsedUrl = url.parse(redirectUrl, true);
    const authCode = parsedUrl.query.auth_code;
    if (!authCode) {
        throw new Error(`Could not extract auth_code from redirect URL: ${redirectUrl}`);
    }
    console.log(`✅ Auth Code successfully generated: ${authCode.slice(0, 15)}...`);

    // Step 5: Exchange authorization code for access token
    console.log("Step 5: Exchanging auth code for final Fyers API access token...");
    const fyersObj = new fyersModel();
    fyersObj.setAppId(APP_ID);
    fyersObj.setRedirectUrl(REDIRECT_URI);

    const tokenResponse = await fyersObj.generate_access_token({
        client_id: APP_ID,
        secret_key: SECRET_KEY,
        auth_code: authCode
    });

    if (!tokenResponse || tokenResponse.s !== "ok" || !tokenResponse.access_token) {
        throw new Error(`Token generation failed: ${JSON.stringify(tokenResponse)}`);
    }

    const accessToken = tokenResponse.access_token;
    console.log("🎉 Programmatic login complete! Access token generated successfully.");
    
    saveTokenToCache(accessToken, APP_ID);
    return { accessToken, appId: APP_ID };
}

// ============================================================
// CONFIGURATION LOADERS (JSON settings.json)
// ============================================================

function getPythonWeekday() {
    // JS: 0=Sun, 1=Mon, ..., 6=Sat
    // Python: 0=Mon, ..., 5=Sat, 6=Sun
    const day = new Date().getDay();
    return day === 0 ? 6 : day - 1;
}

function getSettings() {
    try {
        const settingsFile = path.join(__dirname, 'settings.json');
        if (fs.existsSync(settingsFile)) {
            return JSON.parse(fs.readFileSync(settingsFile, 'utf-8'));
        }
    } catch (e) {
        console.warn(`⚠️ Error reading settings.json: ${e.message}. Using defaults.`);
    }
    return {
        expiry_date: "",
        thresholds: {
            "0": { threshold: 2000000, is_expiry_day: false, last_updated: "Default" },
            "1": { threshold: 3000000, is_expiry_day: true, last_updated: "Default" },
            "2": { threshold: 3000000, is_expiry_day: false, last_updated: "Default" },
            "3": { threshold: 3000000, is_expiry_day: false, last_updated: "Default" },
            "4": { threshold: 2000000, is_expiry_day: false, last_updated: "Default" }
        }
    };
}

function getVolumeThreshold() {
    const settings = getSettings();
    const weekday = String(getPythonWeekday());
    return parseInt(settings.thresholds?.[weekday]?.threshold || 100000);
}

function getExpiryDate() {
    const settings = getSettings();
    const expiryDate = settings.expiry_date || "";
    if (expiryDate) {
        console.log(`📅 Expiry date loaded: ${expiryDate}`);
        return expiryDate;
    }
    
    // Fallback: next Thursday
    const today = new Date();
    const dayOfWeek = today.getDay(); // 0=Sun, ..., 6=Sat
    // Target next Thursday (4)
    let daysAhead = (4 - dayOfWeek + 7) % 7;
    if (daysAhead === 0) daysAhead = 7;
    
    const nextThursday = new Date(today);
    nextThursday.setDate(today.getDate() + daysAhead);
    
    const dd = String(nextThursday.getDate()).padStart(2, '0');
    const mm = String(nextThursday.getMonth() + 1).padStart(2, '0');
    const yyyy = nextThursday.getFullYear();
    
    const fallback = `${dd}-${mm}-${yyyy}`;
    console.log(`⚠️ Using fallback expiry date: ${fallback}`);
    return fallback;
}

// ============================================================
// GENERAL HELPERS
// ============================================================

async function getLtp() {
    const res = await fyers.getQuotes([SYMBOL]);
    if (res && res.s === "ok" && Array.isArray(res.d) && res.d.length > 0) {
        return parseFloat(res.d[0].v.lp);
    }
    throw new Error(`Failed to fetch LTP for ${SYMBOL}: ${JSON.stringify(res)}`);
}

function extractStrike(symbol) {
    try {
        const core = symbol.split(":")[1].slice(0, -2);
        let idx = 0;
        while (idx < core.length && !/^\d$/.test(core[idx])) {
            idx++;
        }
        const strikePart = core.slice(idx + 5);
        return parseInt(strikePart);
    } catch (e) {
        return null;
    }
}

async function resolveExpiryTimestamp(expiryDate) {
    const res = await fyers.getOptionChain({ symbol: SYMBOL });
    if (!res || !res.data || !Array.isArray(res.data.expiryData)) {
        throw new Error(`Could not fetch expiry list from Fyers: ${JSON.stringify(res)}`);
    }
    const expiryList = res.data.expiryData;
    console.log("📋 Available expiries:");
    for (const e of expiryList) {
        const marker = e.date === expiryDate ? " ◀ SELECTED" : "";
        console.log(`   ${e.date}  (ts=${e.expiry})  [${e.expiry_flag}]${marker}`);
    }
    for (const e of expiryList) {
        if (e.date === expiryDate) {
            return e.expiry;
        }
    }
    
    const fallbackDate = expiryList[0].date;
    console.warn(`⚠️ Expiry '${expiryDate}' not found. Falling back to nearest active expiry: ${fallbackDate}`);
    return expiryList[0].expiry;
}

async function loadFullOptionChain(expiryDate) {
    const expiryTs = await resolveExpiryTimestamp(expiryDate);
    console.log(`\n📅 Fetching full option chain for expiry: ${expiryDate} (ts=${expiryTs})`);
    
    const data = await fyers.getOptionChain({
        symbol: SYMBOL,
        timestamp: expiryTs
    });

    if (!data || data.code !== 200 || !data.data || !Array.isArray(data.data.optionsChain)) {
        throw new Error(`Option Chain Error: ${JSON.stringify(data)}`);
    }

    fullOptionChainMap = {};
    for (const item of data.data.optionsChain) {
        if (item.strike_price === undefined || item.strike_price === -1) continue;
        const strike = item.strike_price;
        const sym = item.symbol;
        const optType = sym.endsWith("CE") ? "CE" : "PE";
        
        if (!fullOptionChainMap[strike]) {
            fullOptionChainMap[strike] = {};
        }
        fullOptionChainMap[strike][optType] = sym;
    }
    console.log(`✅ Loaded full option chain with ${Object.keys(fullOptionChainMap).length} strikes.`);
}

function getSymbolsFromChain(atm) {
    const symList = [];
    const strikeList = [];
    const sortedStrikes = Object.keys(fullOptionChainMap).map(Number).sort((a, b) => a - b);
    
    for (const strike of sortedStrikes) {
        if (Math.abs(strike - atm) <= STEP * STRIKE_RANGE) {
            if (strike % STEP !== 0) continue;
            strikeList.push(strike);
            for (const optType of ["CE", "PE"]) {
                const sym = fullOptionChainMap[strike][optType];
                if (sym) {
                    symList.push(sym);
                    if (!optionChain[strike]) {
                        optionChain[strike] = {
                            CE: { ltp: 0, vol: 0, prev_vol: 0, chg_vol: 0, oi: 0 },
                            PE: { ltp: 0, vol: 0, prev_vol: 0, chg_vol: 0, oi: 0 }
                        };
                    }
                }
            }
        }
    }
    return {
        symList,
        strikes: Array.from(new Set(strikeList)).sort((a, b) => a - b)
    };
}

async function checkAndShiftAtm(currentIndexLtp) {
    const newAtm = Math.round(currentIndexLtp / STEP) * STEP;
    if (currentAtm === 0) {
        currentAtm = newAtm;
        return;
    }

    if (newAtm !== currentAtm) {
        const oldAtm = currentAtm;
        console.log(`\n🔄 ATM SHIFTED: ${oldAtm} -> ${newAtm} (Index LTP: ${currentIndexLtp})`);

        const result = getSymbolsFromChain(newAtm);
        const newSymbols = result.symList;
        const newStrikes = result.strikes;

        const oldSet = new Set(symbols);
        const newSet = new Set(newSymbols);

        const toUnsubscribe = symbols.filter(s => !newSet.has(s));
        const toSubscribe = newSymbols.filter(s => !oldSet.has(s));

        symbols = newSymbols;
        strikes = newStrikes;
        currentAtm = newAtm;

        // Clean up out of range strikes
        const strikeSet = new Set(strikes);
        for (const strike of Object.keys(optionChain)) {
            if (!strikeSet.has(Number(strike))) {
                delete optionChain[strike];
            }
        }

        // Apply to Fyers WS
        if (fyersWs) {
            if (toUnsubscribe.length > 0) {
                try {
                    fyersWs.unsubscribe(toUnsubscribe, "symbolUpdate");
                    console.log(`📤 Unsubscribed from ${toUnsubscribe.length} old option symbols.`);
                } catch (err) {
                    console.error("❌ Error unsubscribing:", err.message);
                }
            }
            if (toSubscribe.length > 0) {
                try {
                    fyersWs.subscribe(toSubscribe, "symbolUpdate");
                    console.log(`📥 Subscribed to ${toSubscribe.length} new option symbols.`);
                } catch (err) {
                    console.error("❌ Error subscribing:", err.message);
                }
            }
        }

        // Broadcast reset meta payload to dashboard
        const expiryDate = getExpiryDate();
        const initPayload = {
            type: "init",
            data: optionChain,
            threshold: getVolumeThreshold(),
            symbol: SYMBOL,
            expiry: expiryDate,
            ltp: currentIndexLtp,
            atm: newAtm
        };
        broadcastData(initPayload);
    }
}

// ============================================================
// PROCESSING TICK DATA
// ============================================================

function processTick(data) {
    if (!data || typeof data !== 'object') return;

    const symbol = data.symbol;
    if (!symbol) return;

    if (symbol === SYMBOL) {
        const ltp = data.ltp;
        if (ltp !== undefined && ltp !== null) {
            checkAndShiftAtm(parseFloat(ltp));
        }
        return;
    }

    const strike = extractStrike(symbol);
    if (!strike || !optionChain[strike]) return;

    const optType = symbol.endsWith("CE") ? "CE" : "PE";
    let updated = false;

    if (data.ltp !== undefined && data.ltp !== null) {
        optionChain[strike][optType].ltp = parseFloat(data.ltp);
        updated = true;
    }

    const vol = data.vol_traded_today !== undefined ? data.vol_traded_today : data.volume;
    if (vol !== undefined && vol !== null) {
        const parsedVol = parseInt(vol);
        const prevVol = optionChain[strike][optType].vol;
        if (parsedVol !== prevVol) {
            if (prevVol === 0) {
                optionChain[strike][optType].vol = parsedVol;
                return;
            }

            optionChain[strike][optType].prev_vol = prevVol;
            optionChain[strike][optType].vol = parsedVol;
            const chg = parsedVol - prevVol;
            optionChain[strike][optType].chg_vol = chg;
            updated = true;

            if (chg > 0) {
                const threshold = getVolumeThreshold();
                if (chg > threshold && optionChain[strike][optType].ltp > 10) {
                    const now = new Date();
                    alerted[symbol] = { spike: chg, time: now.getTime() };
                    
                    const msg = `🚨 VOLUME SPIKE ALERT
${symbol}
Strike: ${strike} ${optType}
Change: ${chg.toLocaleString('en-IN')}
Current Vol: ${parsedVol.toLocaleString('en-IN')}
Prev Vol: ${prevVol.toLocaleString('en-IN')}
LTP: ${optionChain[strike][optType].ltp.toFixed(2)}
OI: ${optionChain[strike][optType].oi.toLocaleString('en-IN')}
Threshold used: ${threshold.toLocaleString('en-IN')}`;
                    console.log(msg);

                    const alertPayload = {
                        type: "alert",
                        timestamp: now.toLocaleTimeString('en-IN', { hour12: false }) + "." + String(now.getMilliseconds()).padStart(3, '0'),
                        symbol: symbol,
                        strike: strike,
                        opt_type: optType,
                        chg: chg,
                        vol: parsedVol,
                        prev_vol: prevVol,
                        ltp: optionChain[strike][optType].ltp,
                        oi: optionChain[strike][optType].oi,
                        threshold: threshold
                    };
                    broadcastData(alertPayload);
                }
            }
        }
    }

    if (data.oi !== undefined && data.oi !== null) {
        optionChain[strike][optType].oi = parseInt(data.oi);
        updated = true;
    }

    if (updated) {
        const now = new Date();
        const tickPayload = {
            type: "tick",
            timestamp: now.toLocaleTimeString('en-IN', { hour12: false }) + "." + String(now.getMilliseconds()).padStart(3, '0'),
            symbol: symbol,
            strike: strike,
            opt_type: optType,
            ltp: optionChain[strike][optType].ltp,
            vol: optionChain[strike][optType].vol,
            prev_vol: optionChain[strike][optType].prev_vol,
            chg_vol: optionChain[strike][optType].chg_vol,
            oi: optionChain[strike][optType].oi,
            threshold: getVolumeThreshold()
        };
        broadcastData(tickPayload);
    }
}

function onMessage(msg) {
    try {
        if (!msg) return;
        let data = msg;
        if (typeof msg === 'string') {
            data = JSON.parse(msg);
        }
        
        if (data.symbol) {
            processTick(data);
        } else if (data.d) {
            if (Array.isArray(data.d)) {
                for (const item of data.d) {
                    processTick(item);
                }
            } else if (typeof data.d === 'object') {
                processTick(data.d);
            }
        }
    } catch (e) {
        console.error("onMessage error:", e);
    }
}

// ============================================================
// WEBSOCKET EVENTS & RUNTIME LOGICS
// ============================================================

function startFyersWebsocket() {
    console.log("Connecting to Fyers Data WebSocket...");
    wsConnected = false;
    wsClosed = false;

    const accessTokenStr = `${CLIENT_ID}:${ACCESS_TOKEN}`;
    fyersWs = new fyersDataSocket(accessTokenStr, "", false);

    fyersWs.on("connect", () => {
        console.log("✅ Fyers WebSocket Connected");
        wsConnected = true;
        wsClosed = false;
        
        const allSyms = [...symbols, SYMBOL];
        fyersWs.subscribe(allSyms, "symbolUpdate");
        console.log(`Subscribed to ${allSyms.length} symbol contracts.`);
    });

    fyersWs.on("message", (msg) => {
        onMessage(msg);
    });

    fyersWs.on("error", (err) => {
        console.error(`❌ WS Error: ${err}`);
        wsConnected = false;
    });

    fyersWs.on("close", (code) => {
        console.log(`⚠️ Fyers WS Closed: ${code}. Reconnecting in ${WS_RECONNECT_DELAY}s...`);
        wsConnected = false;
        wsClosed = true;
        
        setTimeout(() => {
            console.log("Attempting to reconnect Fyers WebSocket...");
            fyersWs.connect();
        }, WS_RECONNECT_DELAY * 1000);
    });

    fyersWs.connect();
}

// ============================================================
// LIVE CONSOLE TABULAR DISPLAY
// ============================================================

function startConsoleTablePrint() {
    setInterval(() => {
        const threshold = getVolumeThreshold();
        console.log("\n" + "=".repeat(140));
        console.log(
            `${'CE OI'.padStart(10)} ${'CE PREV'.padStart(10)} ${'CE CHG'.padStart(10)} ${'CE VOL'.padStart(10)} ${'CE LTP'.padStart(10)}` +
            ` | ${'STRIKE'.padEnd(10).padStart(10)} | ` +
            `${'PE LTP'.padStart(10)} ${'PE VOL'.padStart(10)} ${'PE CHG'.padStart(10)} ${'PE PREV'.padStart(10)} ${'PE OI'.padStart(10)}` +
            `  [threshold=${threshold.toLocaleString('en-IN')}]`
        );
        console.log("=".repeat(140));
        
        let found = false;
        const strikesCopy = [...strikes];
        for (const strike of strikesCopy) {
            if (!optionChain[strike]) continue;
            const ce = optionChain[strike].CE;
            const pe = optionChain[strike].PE;
            
            if (ce.chg_vol > threshold || pe.chg_vol > threshold) {
                found = true;
                const ceFlag = ce.chg_vol > threshold ? "🔥" : "  ";
                const peFlag = pe.chg_vol > threshold ? "🔥" : "  ";
                
                console.log(
                    `${ce.oi.toString().padStart(10)} ${ce.prev_vol.toString().padStart(10)} ${ce.chg_vol.toString().padStart(10)} ${ce.vol.toString().padStart(10)}${ceFlag} ${ce.ltp.toFixed(2).padStart(10)}` +
                    ` | ${strike.toString().padStart(5).padEnd(10)} | ` +
                    `${pe.ltp.toFixed(2).padStart(10)} ${pe.vol.toString().padStart(10)}${peFlag} ${pe.chg_vol.toString().padStart(10)} ${pe.prev_vol.toString().padStart(10)} ${pe.oi.toString().padStart(10)}`
                );
            }
        }
        
        if (!found) {
            console.log("⚠️  No volume spike yet...");
        }
        console.log("=".repeat(140));
    }, REFRESH_INTERVAL * 1000);
}

// ============================================================
// WEBSOCKET BROADCASTER SERVER (LOCAL DASHBOARD CLIENTS)
// ============================================================

function runWsServer() {
    wss = new WebSocket.Server({ port: 8765 });
    console.log("🔌 WebSocket server started on ws://localhost:8765");

    wss.on('connection', async (ws) => {
        console.log("Dashboard client connected.");
        const expiryDate = getExpiryDate();
        let ltpVal = 0.0;
        let atmVal = 0;
        try {
            ltpVal = await getLtp();
            atmVal = Math.round(ltpVal / STEP) * STEP;
        } catch (e) {}

        ws.send(JSON.stringify({
            type: "init",
            data: optionChain,
            threshold: getVolumeThreshold(),
            symbol: SYMBOL,
            expiry: expiryDate,
            ltp: ltpVal,
            atm: atmVal
        }));

        ws.on('error', (err) => {
            console.error("Dashboard WS error:", err);
        });

        ws.on('close', () => {
            console.log("Dashboard client disconnected.");
        });
    });
}

function broadcastData(messageObj) {
    if (!wss) return;
    const msgStr = JSON.stringify(messageObj);
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(msgStr);
        }
    });
}

// ============================================================
// EXPRESS WEB SERVER (LOCAL HTML DASHBOARDS)
// ============================================================

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get(['/', '/index.html'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get(['/fyer', '/fyer.html'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'fyer.html'));
});

app.get('/api/settings', (req, res) => {
    try {
        const settingsFile = path.join(__dirname, 'settings.json');
        if (fs.existsSync(settingsFile)) {
            const data = fs.readFileSync(settingsFile, 'utf-8');
            res.json(JSON.parse(data));
        } else {
            res.status(404).json({ error: "Settings file not found" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/settings', (req, res) => {
    try {
        const settingsFile = path.join(__dirname, 'settings.json');
        const newSettings = req.body;
        fs.writeFileSync(settingsFile, JSON.stringify(newSettings, null, 4));

        const weekday = String(getPythonWeekday());
        const metaPayload = {
            type: "meta",
            expiry: newSettings.expiry_date,
            threshold: parseInt(newSettings.thresholds?.[weekday]?.threshold || 100000)
        };
        broadcastData(metaPayload);

        res.json({ status: "success" });
    } catch (e) {
        res.status(500).json({ status: "error", message: e.message });
    }
});

function runHttpServer() {
    const PORT = 8080;
    app.listen(PORT, () => {
        console.log(`🌍 Web server started at http://localhost:${PORT}`);
    });
}

// ============================================================
// MAIN RETRY LOGICS & CONNECT LOOP
// ============================================================

async function verifyToken() {
    try {
        const testQuote = await fyers.getQuotes([SYMBOL]);
        if (!testQuote || testQuote.s !== "ok") {
            throw new Error(`Token verification failed: ${JSON.stringify(testQuote)}`);
        }
        console.log("✅ Token verification successful.");
        return true;
    } catch (e) {
        console.log(`❌ Token verification failed: ${e.message}. Performing fresh login...`);
        return false;
    }
}

async function loginAndConnect() {
    const expiryDate = getExpiryDate();

    // Preload option chain map
    await loadFullOptionChain(expiryDate);

    const ltp = await getLtp();
    currentAtm = Math.round(ltp / STEP) * STEP;
    console.log(`\nLTP: ${ltp}  |  ATM: ${currentAtm}  |  Expiry: ${expiryDate}`);

    const result = getSymbolsFromChain(currentAtm);
    symbols = result.symList;
    strikes = result.strikes;
    console.log(`Total symbols: ${symbols.length}`);

    // Send metadata to active WebSocket clients
    const metaPayload = {
        type: "meta",
        symbol: SYMBOL,
        expiry: expiryDate,
        ltp: ltp,
        atm: currentAtm,
        threshold: getVolumeThreshold()
    };
    broadcastData(metaPayload);

    startFyersWebsocket();

    // Block connection process monitoring using checking variables
    return new Promise((resolve) => {
        const checkInterval = setInterval(() => {
            if (wsClosed || !wsConnected) {
                clearInterval(checkInterval);
                resolve(false);
            }
        }, 1000);
    });
}

async function runWithRetry() {
    let attempt = 0;
    while (attempt < MAX_RETRIES) {
        attempt++;
        console.log("\n" + "=".repeat(60));
        console.log(`🔄 Connection attempt ${attempt} — ${new Date().toLocaleString('en-IN')}`);
        console.log("=".repeat(60));
        
        try {
            await loginAndConnect();
        } catch (e) {
            console.error(`⚠️ Attempt ${attempt} failed: ${e.message}`);
            // Check for critical auth parameters (e.g. 400 Bad Request / Account Blocked)
            if (e.message.includes("Account blocked") || e.message.includes("lockout") || e.response?.status === 400) {
                console.error("\n❌ CRITICAL AUTHENTICATION ERROR");
                console.error("❌ Credentials may be invalid or Fyers account is blocked.");
                console.error("❌ Program exiting immediately to prevent lockout.");
                process.exit(1);
            }
            if (e.response?.status === 429) {
                console.warn("⚠️ Fyers Rate Limit Hit (429). Sleeping for 60 seconds...");
                await new Promise(r => setTimeout(r, 60000));
            }
        }

        if (attempt < MAX_RETRIES) {
            console.log(`⏳ Reconnecting in ${RETRY_DELAY}s (attempt ${attempt}/${MAX_RETRIES})…`);
            await new Promise(r => setTimeout(r, RETRY_DELAY * 1000));
        }
    }
}

async function main() {
    await checkLicense();

    fyers = new fyersModel({
        path: "",
        enableLogging: false
    });
    fyers.setAppId(APP_ID);

    let isTokenValid = false;
    if (loadCachedToken()) {
        fyers.setAccessToken(ACCESS_TOKEN);
        isTokenValid = await verifyToken();
    }

    if (!isTokenValid) {
        const cachePath = path.join(__dirname, 'access_token.json');
        if (fs.existsSync(cachePath)) {
            try {
                fs.unlinkSync(cachePath);
            } catch (err) {}
        }
        const authData = await performLogin();
        ACCESS_TOKEN = authData.accessToken;
        CLIENT_ID = authData.appId;
        fyers.setAccessToken(ACCESS_TOKEN);
    }

    // Start local Express and WS Broadcaster
    runHttpServer();
    runWsServer();

    // Start printing tabular data on terminal
    startConsoleTablePrint();

    // Start Fyers WS connection and run retrier loop
    await runWithRetry();
}

main().catch(err => {
    console.error("Fatal error in option chain scanner:", err);
    process.exit(1);
});
