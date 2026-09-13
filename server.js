const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const mineflayer = require("mineflayer");

// Lightweight .env loader (no extra package required).
// Keep secrets and Microsoft account details in .env, never in the website.
(function loadDotEnv() {
    const envPath = path.join(__dirname, ".env");
    if (!fs.existsSync(envPath)) return;

    for (const rawLine of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        const index = line.indexOf("=");
        if (index <= 0) continue;
        const key = line.slice(0, index).trim();
        let value = line.slice(index + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
        }
        if (process.env[key] === undefined) process.env[key] = value;
    }
})();

const app = express();
console.log("[BOOT] DonutMine server.js loaded.");

const PORT = 3000;
const HOST = "0.0.0.0";

const RECEIVER = "ZynqelYT";
const MINECRAFT_HOST = process.env.MC_HOST || "play.donutsmp.net";
const MINECRAFT_PORT = Number(process.env.MC_PORT || 25565);

const DATA_FILE = path.join(__dirname, "donutmine-data.json");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* =========================================================
   VPN / PROXY BLOCKER
   Uses ProxyCheck when VPN_BLOCKER_API_KEY is configured.
   Local/private addresses are always allowed for local development.
========================================================= */
const VPN_BLOCKER_ENABLED = String(process.env.VPN_BLOCKER || "1").toLowerCase() !== "0";
const VPN_BLOCKER_API_KEY = String(process.env.VPN_BLOCKER_API_KEY || "").trim();
const vpnCache = new Map();

function clientIp(req) {
    const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    const raw = forwarded || req.socket.remoteAddress || "";
    return raw.replace(/^::ffff:/, "");
}

function isPrivateIp(ip) {
    if (!ip) return true;
    if (ip === "127.0.0.1" || ip === "::1" || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.16.") || ip.startsWith("172.17.") || ip.startsWith("172.18.") || ip.startsWith("172.19.") || ip.startsWith("172.2") || ip.startsWith("172.30.") || ip.startsWith("172.31.")) return true;
    return false;
}

async function vpnCheck(ip) {
    if (!VPN_BLOCKER_ENABLED || isPrivateIp(ip) || !VPN_BLOCKER_API_KEY) return { blocked: false, checked: false };
    const cached = vpnCache.get(ip);
    if (cached && cached.expiresAt > Date.now()) return cached.result;

    try {
        const url = `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${encodeURIComponent(VPN_BLOCKER_API_KEY)}&vpn=1&asn=1`;
        const response = await fetch(url, { headers: { "accept": "application/json" } });
        if (!response.ok) return { blocked: false, checked: false };
        const json = await response.json();
        const record = json?.[ip] || {};
        const blocked = String(record.proxy || "no").toLowerCase() === "yes" || String(record.vpn || "no").toLowerCase() === "yes";
        const result = { blocked, checked: true, type: record.type || "unknown", provider: record.provider || "" };
        vpnCache.set(ip, { result, expiresAt: Date.now() + 10 * 60 * 1000 });
        return result;
    } catch (error) {
        console.error("[VPN] check failed:", error.message);
        return { blocked: false, checked: false };
    }
}

app.use("/api", async (req, res, next) => {
    if (!VPN_BLOCKER_ENABLED || req.path === "/health") return next();
    const ip = clientIp(req);
    const result = await vpnCheck(ip);
    if (result.blocked) {
        console.warn(`[VPN BLOCK] ${ip} ${result.type || "proxy"}`);
        return res.status(403).json({ error: "VPN/proxy connections are not allowed on DONUTMINE." });
    }
    next();
});

app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        server: "online",
        paymentReader: "online",
        receiver: RECEIVER,
        provablyFair: true
    });
});


let data = {
    users: {},
    transactions: []
};

if (fs.existsSync(DATA_FILE)) {
    try {
        data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    } catch {
        console.log("Could not read database, creating new one.");
    }
}

if (!data.users) data.users = {};
if (!data.transactions) data.transactions = [];
if (!data.promoCodes) data.promoCodes = {};


function saveData() {
    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(data, null, 2)
    );
}

function randomId() {
    return crypto.randomBytes(16).toString("hex");
}

function randomLoginAmount() {
    return Math.floor(Math.random() * 501) + 500;
}

function moneyNumber(value) {
    if (typeof value === "number") {
        return Number.isFinite(value) ? value : null;
    }

    if (typeof value !== "string") return null;

    const raw = value
        .trim()
        .toLowerCase()
        .replace(/[$,\s]/g, "");

    if (!raw) return null;

    let multiplier = 1;

    if (raw.endsWith("k")) {
        multiplier = 1000;
        value = raw.slice(0, -1);
    } else if (raw.endsWith("m")) {
        multiplier = 1000000;
        value = raw.slice(0, -1);
    } else if (raw.endsWith("b")) {
        multiplier = 1000000000;
        value = raw.slice(0, -1);
    } else {
        value = raw;
    }

    const number = Number(value);

    if (!Number.isFinite(number)) return null;

    const result = Math.round(number * multiplier);

    if (!Number.isSafeInteger(result)) return null;

    return result;
}


/* =========================================================
   SESSIONS / REQUESTS
========================================================= */

const sessions = new Map();
const authRequests = new Map();
const depositRequests = new Map();


function getSession(req) {
    const token =
        req.headers["x-donutmine-session"];

    if (!token) return null;

    return sessions.get(token) || null;
}


function requireSession(req, res) {

    const session = getSession(req);

    if (!session) {
        res.status(401).json({
            error: "You are not logged in."
        });

        return null;
    }

    return session;
}


/* =========================================================
   STAFF AUTH
========================================================= */
const STAFF_EMAIL = process.env.STAFF_EMAIL || "admin123@gmail.com";
const STAFF_PASSWORD = process.env.STAFF_PASSWORD || "admin123123123@@";
const staffSessions = new Map();

function getStaff(req) {
    const token = String(req.headers["x-donutmine-staff"] || "");
    return token ? staffSessions.get(token) || null : null;
}

app.post("/api/staff/login", (req, res) => {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");
    if (email !== STAFF_EMAIL.toLowerCase() || password !== STAFF_PASSWORD) {
        return res.status(401).json({ error: "Invalid staff credentials." });
    }
    const token = crypto.randomBytes(32).toString("hex");
    // Staff is also represented by the ZynqelYT player account so the same
    // authenticated account/session can use account-scoped features such as
    // promo redemption. Staff permissions remain separate from player auth.
    const staffKey = usernameKey("ZynqelYT");
    if (!data.users[staffKey]) {
        data.users[staffKey] = { username: "ZynqelYT", balance: 0, createdAt: Date.now() };
        saveData();
    }
    const playerSession = crypto.randomBytes(32).toString("hex");
    sessions.set(playerSession, { key: staffKey, username: "ZynqelYT", createdAt: Date.now(), isStaffPlayer: true });
    staffSessions.set(token, { email: STAFF_EMAIL, createdAt: Date.now(), playerSession });
    res.json({ success: true, token, playerSession, email: STAFF_EMAIL, username: "ZynqelYT", skinUsername: "ZynqelYT", balance: Number(data.users[staffKey].balance || 0) });
});

app.get("/api/staff/me", (req, res) => {
    const staff = getStaff(req);
    if (!staff) return res.status(401).json({ error: "Staff session expired." });
    const users = Object.values(data.users || {});
    const games = (data.transactions || []).filter(t => t.type === "game");
    const totalBalance = users.reduce((n, u) => n + Number(u.balance || 0), 0);
    res.json({ authenticated: true, email: staff.email, username: "ZynqelYT", skinUsername: "ZynqelYT", stats: { users: users.length, gamesPlayed: games.length, transactions: (data.transactions || []).length, totalBalance }, promoCodes: promoList() });
});

app.post("/api/staff/logout", (req, res) => {
    const token = String(req.headers["x-donutmine-staff"] || "");
    if (token) {
        const staff = staffSessions.get(token);
        if (staff?.playerSession) sessions.delete(staff.playerSession);
        staffSessions.delete(token);
    }
    res.json({ success: true });
});


/* =========================================================
   STAFF BALANCE CONTROL
========================================================= */

app.post("/api/staff/balance/add", (req, res) => {
    const staff = getStaff(req);
    if (!staff) return res.status(401).json({ error: "Staff session expired." });

    const username = String(req.body?.username || "").trim();
    const amount = moneyNumber(req.body?.amount);

    if (!validUsername(username)) {
        return res.status(400).json({ error: "Enter a valid Minecraft username." });
    }
    if (amount === null || !Number.isSafeInteger(amount) || amount <= 0) {
        return res.status(400).json({ error: "Enter a valid positive balance amount." });
    }
    if (amount > 1000000000000) {
        return res.status(400).json({ error: "Balance amount is too large." });
    }

    const key = usernameKey(username);
    let user = data.users[key];

    if (!user) {
        user = data.users[key] = {
            username,
            balance: 0,
            createdAt: Date.now()
        };
    }

    user.balance = Number(user.balance || 0) + amount;

    data.transactions.push({
        id: randomId(),
        type: "staff_balance",
        username: user.username,
        amount,
        description: `Staff balance credit by ${staff.email}`,
        createdAt: Date.now()
    });

    saveData();

    console.log(`[STAFF BALANCE] ${staff.email} added $${amount} to ${user.username}. New balance: $${user.balance}`);

    res.json({
        success: true,
        username: user.username,
        amount,
        balance: user.balance
    });
});

/* =========================================================
   PROMO CODES + STAFF TOOLS
========================================================= */
function normalizePromoCode(value) {
    return String(value || "").trim().toUpperCase();
}

function randomPromoCode() {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const part = () => Array.from(crypto.randomBytes(3), b => alphabet[b % alphabet.length]).join("");
    let code;
    do { code = `${part()}-${part()}-${part()}`; } while (data.promoCodes[code]);
    return code;
}

function validPromoCode(code) {
    return /^[A-Z0-9_-]{1,128}$/.test(code);
}

function promoList() {
    return Object.values(data.promoCodes || {}).map(p => ({
        code: p.code,
        reward: p.reward,
        maxUses: p.maxUses,
        uses: Array.isArray(p.redeemedBy) ? p.redeemedBy.length : 0,
        createdAt: p.createdAt
    })).sort((a,b) => b.createdAt - a.createdAt);
}

app.post("/api/staff/promo/create", (req, res) => {
    const staff = getStaff(req);
    if (!staff) return res.status(401).json({ error: "Staff session expired." });

    let code = normalizePromoCode(req.body?.code);
    const reward = moneyNumber(req.body?.reward);
    const maxUses = Number(req.body?.maxUses);

    if (!code || code === "AUTO") code = randomPromoCode();
    if (!validPromoCode(code)) return res.status(400).json({ error: "Promo code may contain only letters, numbers, _ or - and can be 1–128 characters." });
    if (data.promoCodes[code]) return res.status(409).json({ error: "That promo code already exists." });
    if (reward === null || !Number.isSafeInteger(reward) || reward <= 0) return res.status(400).json({ error: "Enter a valid positive reward." });
    if (!Number.isSafeInteger(maxUses) || maxUses < 1 || maxUses > 1000000) return res.status(400).json({ error: "Max uses must be between 1 and 1,000,000." });

    data.promoCodes[code] = {
        code,
        reward,
        maxUses,
        redeemedBy: [],
        createdAt: Date.now(),
        createdBy: staff.email
    };
    saveData();
    console.log(`[PROMO] ${staff.email} created ${code} for $${reward} (${maxUses} uses)`);
    res.json({ success: true, code, reward, maxUses });
});

app.post("/api/staff/promo/delete", (req, res) => {
    const staff = getStaff(req);
    if (!staff) return res.status(401).json({ error: "Staff session expired." });
    const code = normalizePromoCode(req.body?.code);
    if (!data.promoCodes[code]) return res.status(404).json({ error: "Promo code not found." });
    delete data.promoCodes[code];
    saveData();
    console.log(`[PROMO] ${staff.email} deleted ${code}`);
    res.json({ success: true });
});

app.post("/api/promo/redeem", (req, res) => {
    const session = requireSession(req, res);
    if (!session) return;

    const code = normalizePromoCode(req.body?.code);
    const promo = data.promoCodes[code];
    if (!promo) return res.status(404).json({ error: "Invalid promo code." });

    if (!Array.isArray(promo.redeemedBy)) promo.redeemedBy = [];
    const accountKey = usernameKey(session.username);
    if (promo.redeemedBy.includes(accountKey)) {
        return res.status(409).json({ error: "You have already redeemed this promo code on this account." });
    }
    if (promo.redeemedBy.length >= promo.maxUses) {
        return res.status(409).json({ error: "This promo code has reached its usage limit." });
    }

    const user = data.users[session.key];
    if (!user) return res.status(401).json({ error: "Account not found." });

    user.balance = Number(user.balance || 0) + Number(promo.reward || 0);
    promo.redeemedBy.push(accountKey);
    data.transactions.push({
        id: randomId(),
        type: "promo",
        code,
        username: user.username,
        amount: Number(promo.reward || 0),
        createdAt: Date.now()
    });
    saveData();

    console.log(`[PROMO] ${user.username} redeemed ${code} for $${promo.reward}`);
    res.json({ success: true, code, reward: promo.reward, balance: user.balance, remainingUses: Math.max(0, promo.maxUses - promo.redeemedBy.length) });
});

/* =========================================================
   MINECRAFT BOT
========================================================= */

/* =========================================================
   MINECRAFT BOT
========================================================= */

let bot = null;
let botOnline = false;
let reconnectTimer = null;
let botStarting = false;

function startBot() {
    if (botStarting) return;

    botStarting = true;

    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    if (bot) {
        try {
            bot.removeAllListeners();
            bot.quit();
        } catch {}

        bot = null;
    }

    const minecraftEmail =
        process.env.MC_USERNAME;

    if (!minecraftEmail) {
        console.error(
            "[BOT] MC_USERNAME is not configured."
        );

        console.error(
            "[BOT] MC_USERNAME must be the Microsoft/Minecraft account email."
        );

        botStarting = false;
        botOnline = false;
        return;
    }

    console.log(
        `[BOT] Connecting to ${MINECRAFT_HOST}:${MINECRAFT_PORT}...`
    );

    console.log(
        "[BOT] Authentication: Microsoft"
    );

    bot = mineflayer.createBot({
        host: MINECRAFT_HOST,
        port: MINECRAFT_PORT,

        /*
         * IMPORTANT:
         * This is the Microsoft account EMAIL,
         * not the Minecraft username.
         */
        username: minecraftEmail,

        auth: "microsoft",

        /*
         * Let Mineflayer detect the server version.
         */
        version: false,

        /*
         * Keep the connection alive longer if
         * the server is slow.
         */
        checkTimeoutInterval: 300000,

        /*
         * Cache Microsoft authentication.
         */
        profilesFolder: path.join(
            __dirname,
            "minecraft-auth"
        )
    });

    bot.once("spawn", () => {
        botStarting = false;
        botOnline = true;

        console.log("");
        console.log(
            "========================================"
        );
        console.log(
            "[BOT] MINECRAFT BOT CONNECTED"
        );
        console.log(
            `[BOT] Username: ${bot.username}`
        );
        console.log(
            `[BOT] Server: ${MINECRAFT_HOST}`
        );
        console.log(
            "========================================"
        );
        console.log("");
    });

    /*
     * Microsoft device-code login.
     *
     * Mineflayer will print a code here the
     * first time authentication is required.
     */
    bot.on("login", () => {
        console.log(
            "[BOT] Authentication successful."
        );
    });

    /*
     * IMPORTANT:
     * Minecraft chat stays backend-only.
     */
    bot.on("messagestr", message => {
        handleMinecraftMessage(message);
    });

    /*
     * Show the REAL kick reason.
     */
    bot.on("kicked", reason => {
        botOnline = false;

        console.error("");
        console.error(
            "========================================"
        );
        console.error(
            "[BOT] KICKED FROM DONUTSMP"
        );
        console.error(
            "========================================"
        );

        console.error(
            typeof reason === "string"
                ? reason
                : JSON.stringify(reason, null, 2)
        );

        console.error(
            "========================================"
        );
        console.error("");
    });

    bot.on("error", error => {
        botOnline = false;

        console.error(
            "[BOT] ERROR:",
            error?.stack || error?.message || error
        );
    });

    bot.on("end", () => {
        botOnline = false;
        botStarting = false;
        bot = null;

        console.error(
            "[BOT] Minecraft bot disconnected."
        );

        scheduleReconnect();
    });
}

function scheduleReconnect() {
    if (reconnectTimer) return;

    reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        startBot();
    }, 15000);
}


/* =========================================================
   PAYMENT READER
========================================================= */

function usernameKey(value) {
    // DonutSMP Bedrock names can appear as .Name in chat.
    // Compare with the dot removed so both Name and .Name identify the same player.
    return String(value || "").trim().toLowerCase().replace(/^\./, "");
}

function validUsername(value) {
    return /^\.?[A-Za-z0-9_]{3,16}$/.test(String(value || "").trim());
}

function extractPayment(message) {
    const text = String(message || "")
        .replace(/§[0-9a-fk-or]/gi, "")
        .replace(/\u00a7[0-9a-fk-or]/gi, "")
        .replace(/\s+/g, " ")
        .trim();
    if (!text) return null;

    const NAME = "[.]?[A-Za-z0-9_]{3,16}";
    const MONEY = "\\$?\\s*[0-9][0-9,]*(?:\\.[0-9]+)?(?:[kKmMbBtT])?";
    const receiver = usernameKey(RECEIVER);

    function finish(player, rawAmount) {
        const amount = moneyNumber(rawAmount);
        if (!player || amount === null) return null;
        if (usernameKey(player) === receiver) return null;
        return { player, amount };
    }

    let m;

    // Most DonutSMP-style messages: .Player paid you $123 / Player paid ZynqelYT $123
    m = text.match(new RegExp("^\\s*(" + NAME + ")\\s+(?:paid|sent|gave)\\b.*?" + "(" + MONEY + ")\\s*$", "i"));
    if (m) {
        const result = finish(m[1], m[2]);
        if (result) return result;
    }

    // You received $123 from .Player / Received $123 by .Player
    m = text.match(new RegExp("(?:received|payment|paid|sent)\\b.*?(" + MONEY + ")\\s+(?:from|by)\\s+(" + NAME + ")\\b", "i"));
    if (m) {
        const result = finish(m[2], m[1]);
        if (result) return result;
    }

    // Payment from .Player: $123
    m = text.match(new RegExp("(?:payment|transaction)\\s+(?:from\\s+)?(" + NAME + ")\\s*[:|-]\\s*(" + MONEY + ")", "i"));
    if (m) {
        const result = finish(m[1], m[2]);
        if (result) return result;
    }

    // .Player -> ZynqelYT: $123 / .Player to ZynqelYT $123
    m = text.match(new RegExp("^\\s*(" + NAME + ")\\s*(?:->|to)\\s+[^ ]+.*?(" + MONEY + ")\\s*$", "i"));
    if (m) {
        const result = finish(m[1], m[2]);
        if (result) return result;
    }

    // Reverse form: $123 from .Player / $123 by .Player
    m = text.match(new RegExp("^\\s*(" + MONEY + ")\\s+(?:from|by)\\s+(" + NAME + ")\\s*$", "i"));
    if (m) {
        const result = finish(m[2], m[1]);
        if (result) return result;
    }

    // Fallback for chat prefixes: [Pay] .Player paid you 123
    m = text.match(new RegExp("\\b(" + NAME + ")\\s+(?:paid|sent|gave)\\b.*?(" + MONEY + ")", "i"));
    if (m) {
        const result = finish(m[1], m[2]);
        if (result) return result;
    }

    return null;
}

function processPayment(playerName, amount) {
    const normalized = usernameKey(playerName);

    const numericAmount =
        Number(amount);

    if (!normalized || !Number.isFinite(numericAmount)) {
        return false;
    }

    /*
     * LOGIN VERIFICATION
     */
    for (const [id, request] of authRequests) {

        if (request.status !== "pending") {
            continue;
        }

        if (
            usernameKey(request.username) === normalized &&
            Number(request.amount) === numericAmount
        ) {

            const username =
                request.username;

            if (!data.users[normalized]) {
                data.users[normalized] = {
                    username,
                    balance: 0,
                    createdAt: Date.now()
                };
            }

            const token =
                randomId();

            sessions.set(
                token,
                {
                    username,
                    key: normalized
                }
            );

            request.status =
                "confirmed";

            request.session =
                token;

            request.balance =
                Number(
                    data.users[normalized].balance || 0
                );

            data.transactions.push({
                id: randomId(),
                type: "verification",
                username,
                amount: numericAmount,
                createdAt: Date.now()
            });

            saveData();

            console.log(
                `[PAYMENT] LOGIN VERIFIED: ${username} $${numericAmount}`
            );

            return true;
        }
    }

    /*
     * DEPOSIT
     */
    for (const [id, request] of depositRequests) {

        if (request.status !== "pending") {
            continue;
        }

        if (
            usernameKey(request.username) !== normalized
        ) {
            continue;
        }

        if (
            Number(request.amount) !== numericAmount
        ) {
            continue;
        }

        const user =
            data.users[normalized];

        if (!user) {
            console.log(
                `[PAYMENT] User not found: ${playerName}`
            );

            continue;
        }

        user.balance =
            Number(user.balance || 0) +
            numericAmount;

        request.status =
            "confirmed";

        request.balance =
            user.balance;

        data.transactions.push({
            id: randomId(),
            type: "deposit",
            username: user.username,
            amount: numericAmount,
            createdAt: Date.now()
        });

        saveData();

        console.log("");
        console.log(
            "========================================"
        );
        console.log(
            "[PAYMENT] DEPOSIT CONFIRMED"
        );
        console.log(
            `Player: ${user.username}`
        );
        console.log(
            `Amount: $${numericAmount}`
        );
        console.log(
            `New Balance: $${user.balance}`
        );
        console.log(
            "========================================"
        );
        console.log("");

        return true;
    }

    return false;
}

function handleMinecraftMessage(message) {

    const text = String(message || "");

    console.log(
        "[MC CHAT]",
        text
    );

    const payment =
        extractPayment(text);

    if (!payment) {
        return;
    }

    console.log(
        `[PAYMENT DETECTED] ${payment.player} -> $${payment.amount}`
    );

    const processed =
        processPayment(
            payment.player,
            payment.amount
        );

    if (!processed) {
        console.log(
            `[PAYMENT] No matching pending request for ${payment.player} $${payment.amount}`
        );
    }
}


/* =========================================================
   AUTH
========================================================= */

app.post(
    "/api/auth/start",
    (req, res) => {

        const username =
            String(
                req.body?.username || ""
            ).trim();


        if (!validUsername(username)) {

            return res.status(400).json({
                error:
                    "Enter a valid Minecraft username."
            });
        }


        const amount =
            randomLoginAmount();


        const id =
            randomId();


        authRequests.set(
            id,
            {
                id,
                username,
                amount,
                receiver: RECEIVER,
                status: "pending",
                createdAt: Date.now()
            }
        );


        return res.json({

            id,

            username,

            amount,

            receiver: RECEIVER,

            command:
                `/pay ${RECEIVER} ${amount}`

        });
    }
);


app.get(
    "/api/auth/status/:id",
    (req, res) => {

        const request =
            authRequests.get(req.params.id);


        if (!request) {

            return res.status(404).json({
                error:
                    "Login request not found."
            });
        }


        const response = {

            status:
                request.status,

            verified:
                request.status === "confirmed",

            username:
                request.username,

            amount:
                request.amount,

            receiver:
                request.receiver
        };


        if (request.status === "confirmed") {

            response.session =
                request.session;

            response.balance =
                request.balance;
        }


        res.json(response);
    }
);


/* =========================================================
   SESSION
========================================================= */

app.get(
    "/api/session/:token",
    (req, res) => {

        const session =
            sessions.get(req.params.token);


        if (!session) {

            return res.json({
                valid: false
            });
        }


        const user =
            data.users[session.key];


        if (!user) {

            sessions.delete(
                req.params.token
            );

            return res.json({
                valid: false
            });
        }


        res.json({

            valid: true,

            username:
                user.username,

            balance:
                Number(user.balance || 0),

            session:
                req.params.token
        });
    }
);


/* =========================================================
   ME
========================================================= */

app.get(
    "/api/me",
    (req, res) => {

        const session =
            requireSession(req, res);

        if (!session) return;


        const user =
            data.users[session.key];


        res.json({

            username:
                user.username,

            balance:
                Number(user.balance || 0)
        });
    }
);


/* =========================================================
   DEPOSIT
========================================================= */

app.post(
    "/api/deposit/start",
    (req, res) => {

        const session =
            requireSession(req, res);

        if (!session) return;


        const amount =
            moneyNumber(
                req.body?.amount
            );


        if (
            amount === null ||
            amount <= 0
        ) {

            return res.status(400).json({
                error:
                    "Deposit amount must be greater than $0."
            });
        }


        if (
            amount >
            1000000000
        ) {

            return res.status(400).json({
                error:
                    "Deposit amount is too large."
            });
        }


        const id =
            randomId();


        depositRequests.set(
            id,
            {
                id,

                username:
                    session.username,

                amount,

                receiver:
                    RECEIVER,

                status:
                    "pending",

                createdAt:
                    Date.now()
            }
        );


        res.json({

            id,

            username:
                session.username,

            amount,

            receiver:
                RECEIVER,

            command:
                `/pay ${RECEIVER} ${amount}`
        });
    }
);


app.get(
    "/api/deposit/status/:id",
    (req, res) => {

        const session =
            requireSession(req, res);

        if (!session) return;


        const request =
            depositRequests.get(
                req.params.id
            );


        if (!request) {

            return res.status(404).json({
                error:
                    "Deposit request not found."
            });
        }


        if (
            usernameKey(request.username) !==
            usernameKey(session.username)
        ) {

            return res.status(403).json({
                error:
                    "This deposit request belongs to another account."
            });
        }


        res.json({

            status:
                request.status,

            verified:
                request.status === "confirmed",

            username:
                request.username,

            amount:
                request.amount,

            receiver:
                request.receiver,

            balance:
                request.balance ??
                data.users[
                    session.key
                ]?.balance ??
                0
        });
    }
);


/* =========================================================
   TRANSACTIONS
========================================================= */

app.get(
    "/api/transactions",
    (req, res) => {

        const session =
            requireSession(req, res);

        if (!session) return;


        const transactions =
            data.transactions
            .filter(
                transaction =>
                    transaction.username.toLowerCase() ===
                    session.username.toLowerCase()
            )
            .slice(-100)
            .reverse();


        res.json({
            transactions
        });
    }
);


/* =========================================================
   WITHDRAW
========================================================= */

app.post(
    "/api/withdraw",
    (req, res) => {

        const session =
            requireSession(req, res);

        if (!session) return;


        const amount =
            moneyNumber(
                req.body?.amount
            );


        if (
            amount === null ||
            amount <= 0 ||
            !Number.isSafeInteger(amount)
        ) {

            return res.status(400).json({
                error:
                    "Withdrawal amount must be a positive whole number."
            });
        }


        const user =
            data.users[session.key];


        if (!user) {

            return res.status(404).json({
                error:
                    "User account not found."
            });
        }


        const balance =
            Number(user.balance || 0);


        if(amount > balance){

            return res.status(400).json({
                error:
                    "Insufficient balance."
            });
        }


        if(!bot || !botOnline){

            return res.status(503).json({
                error:
                    "Minecraft payment reader is offline."
            });
        }


        try{

            /*
               Deduct only after we successfully send
               the command to the Minecraft bot.
            */

            bot.chat(
                `/pay ${session.username} ${amount}`
            );


            user.balance =
                balance - amount;


            data.transactions.push({

                id:
                    randomId(),

                type:
                    "withdraw",

                username:
                    user.username,

                amount:
                    -amount,

                createdAt:
                    Date.now()
            });


            saveData();


            res.json({

                success:
                    true,

                username:
                    user.username,

                amount,

                balance:
                    user.balance
            });


        }catch(error){

            console.error(
                "[WITHDRAW]",
                error
            );


            res.status(500).json({
                error:
                    "Could not send Minecraft payment."
            });
        }
    }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    (req, res) => {

        const token =
            req.headers[
                "x-donutmine-session"
            ];


        if(token){
            sessions.delete(token);
        }


        res.json({
            success:true
        });
    }
);


/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/api/health",
    (req, res) => {

        res.json({

            ok:true,

            botOnline:
                botOnline,

            minecraftBot:
                botOnline,

            botStatus:
                botOnline
                    ? "online"
                    : "offline"
        });
    }
);


/* =========================================================
   PROVABLY FAIR ENGINE
========================================================= */

const fairRounds = new Map();

function sha256(value) {
    return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function safeClientSeed(value) {
    const seed = String(value || "").trim();
    if (!seed) return crypto.randomBytes(16).toString("hex");
    return seed.slice(0, 128);
}

function createFairRound(game, sessionKey, requestedClientSeed) {
    const serverSeed = crypto.randomBytes(32).toString("hex");
    const clientSeed = safeClientSeed(requestedClientSeed);
    // Every bet is a completely fresh fair round.
    // The probability bands start over at 0 for every new bet.
    const nonce = 0;
    const serverSeedHash = sha256(serverSeed);
    const id = randomId();

    const round = {
        id,
        game,
        sessionKey,
        serverSeed,
        serverSeedHash,
        clientSeed,
        nonce,
        createdAt: Date.now(),
        used: false
    };

    fairRounds.set(id, round);
    return round;
}

function fairUnit(serverSeed, clientSeed, nonce, cursor = 0) {
    const digest = crypto.createHmac("sha256", serverSeed)
        .update(`${clientSeed}:${nonce}:${cursor}`)
        .digest();
    // 48 bits -> uniform value in [0,1).
    const integer = digest.readUIntBE(0, 6);
    return integer / 0x1000000000000;
}

/*
 * Hidden per-bet distribution.
 * Each bet gets a fresh server seed and a fresh roll in [0,1).
 * The bands are re-applied from zero on EVERY bet: 65% LOSS, 25% WIN, 10% TIE.
 * Nothing accumulates from the previous bet, and these percentages are never sent to the browser.
 */
const OUTCOME_BANDS = Object.freeze({
    LOSS_END: 0.65,
    WIN_END: 0.90
});

function resolveOutcome(round) {
    const r = fairUnit(round.serverSeed, round.clientSeed, round.nonce, 0);

    if (r < OUTCOME_BANDS.LOSS_END) {
        return { outcome: "LOSS", roll: r };
    }

    if (r < OUTCOME_BANDS.WIN_END) {
        return { outcome: "WIN", roll: r };
    }

    return { outcome: "TIE", roll: r };
}

app.post("/api/fair/commit", (req, res) => {
    const session = requireSession(req, res);
    if (!session) return;

    const game = String(req.body?.game || "DICE").trim().toUpperCase();
    if (!game) return res.status(400).json({ error: "Game is required." });

    const round = createFairRound(game, session.key, req.body?.clientSeed);

    res.json({
        id: round.id,
        serverSeedHash: round.serverSeedHash,
        clientSeed: round.clientSeed,
        nonce: round.nonce
    });
});

app.get("/api/fair/round/:id", (req, res) => {
    const session = requireSession(req, res);
    if (!session) return;

    const round = fairRounds.get(String(req.params.id));
    if (!round || round.sessionKey !== session.key) {
        return res.status(404).json({ error: "Fair round not found." });
    }

    res.json({
        id: round.id,
        game: round.game,
        serverSeedHash: round.serverSeedHash,
        clientSeed: round.clientSeed,
        nonce: round.nonce,
        revealed: !!round.revealed,
        serverSeed: round.revealed ? round.serverSeed : undefined
    });
});

/* =========================================================
   GAME ENGINE — SERVER AUTHORITATIVE + PROVABLY FAIR
========================================================= */

const activeGames = new Map();

function freshGameState(round, bet) {
    const game = round.game;
    const seed = round.serverSeed;
    const unit = (cursor) => fairUnit(seed, round.clientSeed, round.nonce, cursor);
    const state = { id: randomId(), roundId: round.id, game, sessionKey: round.sessionKey, bet, createdAt: Date.now(), finished: false };

    // Hidden 65/25/10 bucket. It is derived from the committed seed and restarts every bet.
    state.bucket = resolveOutcome(round).outcome;

    if (game === 'MINES') {
        const cells = Array.from({length:25}, (_,i)=>i);
        for(let i=cells.length-1;i>0;i--){ const j=Math.floor(unit(10+i)*(i+1)); [cells[i],cells[j]]=[cells[j],cells[i]]; }
        state.mines = new Set(cells.slice(0,5));
        state.revealed = [];
        state.multiplier = 1;
    }
    if (game === 'TOWER') {
        state.floor = 0; state.maxFloor = 8;
        state.safe = Array.from({length:8},(_,floor)=>Math.floor(unit(80+floor)*3));
    }
    if (game === 'BLACKJACK') {
        const deck = ['A','2','3','4','5','6','7','8','9','10','J','Q','K'].flatMap(v=>['♠','♥','♦','♣'].map(s=>v+s));
        for(let i=deck.length-1;i>0;i--){const j=Math.floor(unit(150+i)*(i+1));[deck[i],deck[j]]=[deck[j],deck[i]];}
        state.deck=deck; state.player=[deck.pop(),deck.pop()]; state.dealer=[deck.pop(),deck.pop()]; state.stood=false;
    }
    if (game === 'CRASH') {
        // Crash point is hidden until the rocket actually reaches it. A fresh deterministic point per bet.
        // The public UI never receives the hidden 65/25/10 bucket.
        if(state.bucket==='LOSS') state.crashPoint=1.01 + unit(201)*0.48;
        else if(state.bucket==='WIN') state.crashPoint=2.00 + unit(202)*8.00;
        else state.crashPoint=1.50 + unit(203)*0.80;
        state.startedAt=Date.now(); state.cashed=false;
    }
    if (game === 'COINFLIP') state.side = unit(300)>=0.5?'HEADS':'TAILS';
    if (game === 'RUSSIAN ROULETTE') state.chamber = Math.floor(unit(310)*6)+1;
    if (game === 'DONUT ROULETTE') state.pocket = Math.floor(unit(320)*16);
    if (game === 'WHEEL') state.pocket = unit(330);
    if (game === 'PLINKO') state.path = Array.from({length:10},(_,i)=>unit(340+i)>=0.5?1:0);
    if (game === 'CASES' || game === 'STRIP MINE' || game === 'ITEM UPGRADER') state.drop = unit(360);
    if (game === 'CASE BATTLES') state.opponent = unit(370);
    if (game === 'KENO') {
        state.draw = []; const pool=Array.from({length:40},(_,i)=>i+1);
        for(let i=pool.length-1;i>0;i--){const j=Math.floor(unit(400+i)*(i+1));[pool[i],pool[j]]=[pool[j],pool[i]];}
        state.draw=pool.slice(0,10);
    }
    if (game === 'HI-LO') state.nextCard = Math.floor(unit(450)*13)+1;
    if (game === 'SNAKE') { state.score=0; state.moves=0; state.target=state.bucket==='WIN'?18:state.bucket==='TIE'?10:6; }
    if (game === 'DICE') state.roll = unit(500)*100;
    if (game === 'LIMBO') state.multiplier = state.bucket==='WIN' ? 2+unit(510)*8 : state.bucket==='TIE' ? 1.5+unit(511)*1.5 : 1.01+unit(512)*0.7;

    activeGames.set(state.id,state);
    return state;
}

function cardValue(c){ const v=c.slice(0,-1); if(v==='A') return 11; if(['K','Q','J'].includes(v)) return 10; return Number(v); }
function handValue(hand){ let s=hand.reduce((a,c)=>a+cardValue(c),0), ac=hand.filter(c=>c.startsWith('A')).length; while(s>21&&ac--)s-=10; return s; }
function settleState(state, outcome, detail, payout){
    const user=data.users[state.sessionKey];
    if(!user) throw new Error('User account not found.');
    state.finished=true; state.outcome=outcome; state.detail=detail;
    const bet=state.bet;
    const actualPayout = payout ?? (outcome==='WIN'?bet*2:outcome==='TIE'?bet:0);
    const change=actualPayout-bet;
    user.balance=Number(user.balance||0)+change;
    const round=fairRounds.get(state.roundId); if(round){round.used=true;round.revealed=true;round.outcome=outcome;round.roll=fairUnit(round.serverSeed,round.clientSeed,round.nonce,0);}
    data.transactions.push({id:randomId(),type:'game',game:state.game,username:user.username,amount:change,wager:Number(state.bet||0),outcome,fairRound:state.roundId,createdAt:Date.now()});
    saveData();
    return {success:true, outcome, win:outcome==='WIN', tie:outcome==='TIE', payout:actualPayout, balance:user.balance, detail,
        fair:{serverSeedHash:round?.serverSeedHash,serverSeed:round?.serverSeed,clientSeed:round?.clientSeed,nonce:round?.nonce,roll:round?.roll}};
}

app.post('/api/game/start',(req,res)=>{
    const session=requireSession(req,res); if(!session)return;
    const game=String(req.body?.game||'').trim().toUpperCase(); const bet=moneyNumber(req.body?.bet); const commitId=String(req.body?.commitId||'');
    if(!game||!commitId||bet===null||!Number.isSafeInteger(bet)||bet<=0)return res.status(400).json({error:'Invalid game start.'});
    const round=fairRounds.get(commitId); if(!round||round.used||round.sessionKey!==session.key||round.game!==game)return res.status(400).json({error:'Invalid fair round.'});
    const user=data.users[session.key]; if(!user||bet>Number(user.balance||0))return res.status(400).json({error:'Insufficient balance.'});
    const state=freshGameState(round,bet);
    res.json({gameId:state.id,game,state:publicGameState(state)});
});

function publicGameState(s){
    const x={gameId:s.id,game:s.game,bet:s.bet};
    if(s.game==='MINES')Object.assign(x,{revealed:s.revealed,multiplier:s.multiplier});
    if(s.game==='TOWER')Object.assign(x,{floor:s.floor,maxFloor:s.maxFloor});
    if(s.game==='BLACKJACK')Object.assign(x,{player:s.player,dealer:[s.dealer[0],'?'],playerValue:handValue(s.player)});
    if(s.game==='CRASH')Object.assign(x,{multiplier:1.00});
    return x;
}

app.get('/api/game/status/:id',(req,res)=>{
    const session=requireSession(req,res); if(!session)return;
    const s=activeGames.get(String(req.params.id));
    if(!s||s.sessionKey!==session.key||s.finished)return res.status(400).json({error:'Game is no longer active.'});
    if(s.game!=='CRASH')return res.json({active:true});
    const elapsed=(Date.now()-s.startedAt)/1000;
    const mult=Math.max(1,Math.exp(elapsed*0.18));
    if(mult>=s.crashPoint){
        const r=settleState(s,'LOSS',`Rocket crashed at ${s.crashPoint.toFixed(2)}×`,0);
        return res.json({crashed:true,multiplier:s.crashPoint,result:r});
    }
    return res.json({crashed:false,multiplier:mult});
});

app.post('/api/game/action',(req,res)=>{
    const session=requireSession(req,res); if(!session)return;
    const s=activeGames.get(String(req.body?.gameId||'')); if(!s||s.sessionKey!==session.key||s.finished)return res.status(400).json({error:'Game is no longer active.'});
    const action=String(req.body?.action||'').toLowerCase(); const value=req.body?.value;
    try{
        if(s.game==='MINES' && action==='reveal'){
            const i=Number(value); if(!Number.isInteger(i)||i<0||i>24)return res.status(400).json({error:'Invalid tile.'});
            if(s.revealed.includes(i))return res.status(400).json({error:'Tile already revealed.'});
            if(s.mines.has(i)) return res.json(settleState(s,'LOSS','Mine triggered — round lost.',0));
            s.revealed.push(i); s.multiplier=1+Math.pow(s.revealed.length,1.35)*0.18;
            if(s.bucket==='LOSS' && s.revealed.length>=4) return res.json(settleState(s,'LOSS','The minefield collapsed.',0));
            return res.json({success:true,action:'safe',revealed:s.revealed,multiplier:s.multiplier,balance:data.users[session.key].balance});
        }
        if(s.game==='MINES' && action==='cashout'){
            if(!s.revealed.length)return res.status(400).json({error:'Reveal a tile first.'});
            if(s.bucket==='LOSS')return res.json(settleState(s,'LOSS','The round crashed before cash out.',0));
            if(s.bucket==='TIE')return res.json(settleState(s,'TIE','Stake returned.',s.bet));
            return res.json(settleState(s,'WIN',`${s.revealed.length} safe tiles • ${s.multiplier.toFixed(2)}×`,s.bet*Math.max(2, s.multiplier)));
        }
        if(s.game==='TOWER' && action==='choose'){
            const lane=Number(value); if(![0,1,2].includes(lane))return res.status(400).json({error:'Invalid block.'});
            if(s.safe[s.floor]!==lane)return res.json(settleState(s,'LOSS',`Trap on floor ${s.floor+1}.`,0));
            s.floor++;
            if(s.bucket==='LOSS' && s.floor>=2)return res.json(settleState(s,'LOSS','The tower gave way.',0));
            if(s.floor>=s.maxFloor)return res.json(settleState(s,s.bucket==='TIE'?'TIE':'WIN',`Reached floor ${s.floor}.`,s.bucket==='TIE'?s.bet:s.bet*2));
            return res.json({success:true,action:'safe',floor:s.floor,multiplier:(1+s.floor*.32).toFixed(2)});
        }
        if(s.game==='TOWER' && action==='cashout'){
            if(!s.floor)return res.status(400).json({error:'Climb at least one floor.'});
            if(s.bucket==='LOSS')return res.json(settleState(s,'LOSS','The tower collapsed.',0));
            if(s.bucket==='TIE')return res.json(settleState(s,'TIE','Stake returned.',s.bet));
            return res.json(settleState(s,'WIN',`Cashed out at floor ${s.floor}.`,s.bet*Math.max(2,1+s.floor*.32)));
        }
        if(s.game==='BLACKJACK' && (action==='hit'||action==='stand'||action==='double')){
            if(action==='hit'){s.player.push(s.deck.pop());if(handValue(s.player)>21)return res.json(settleState(s,'LOSS','Bust — dealer wins.',0));return res.json({success:true,player:s.player,dealer:[s.dealer[0],'?'],playerValue:handValue(s.player)});}
            if(action==='double'){if(s.bet*2>Number(data.users[session.key].balance||0)+s.bet)return res.status(400).json({error:'Insufficient balance to double.'});s.bet*=2;s.player.push(s.deck.pop());}
            while(handValue(s.dealer)<17)s.dealer.push(s.deck.pop());
            const pv=handValue(s.player),dv=handValue(s.dealer); let o=s.bucket==='LOSS'?'LOSS':s.bucket==='TIE'?'TIE':'WIN';
            if(pv>21)o='LOSS'; else if(dv>21)o='WIN'; else if(pv===dv)o='TIE'; else if(pv>dv)o='WIN'; else o='LOSS';
            if(s.bucket==='WIN'&&o==='LOSS')o='WIN'; if(s.bucket==='LOSS')o='LOSS';
            return res.json(settleState(s,o,`You ${pv} • Dealer ${dv}`,o==='WIN'?s.bet*2:o==='TIE'?s.bet:0));
        }
        if(s.game==='CRASH' && action==='cashout'){
            const mult=Math.max(1,Number(value)||1); if(mult>=s.crashPoint)return res.json(settleState(s,'LOSS',`Rocket crashed at ${s.crashPoint.toFixed(2)}×`,0));
            if(s.bucket==='LOSS')return res.json(settleState(s,'LOSS',`Rocket crashed at ${s.crashPoint.toFixed(2)}×`,0));
            if(s.bucket==='TIE')return res.json(settleState(s,'TIE',`Cashed out at ${mult.toFixed(2)}× • stake returned`,s.bet));
            return res.json(settleState(s,'WIN',`Cashed out at ${mult.toFixed(2)}×`,s.bet*mult));
        }
        if(['DICE','LIMBO','COINFLIP','RUSSIAN ROULETTE','DONUT ROULETTE','WHEEL','PLINKO','CASES','STRIP MINE','CASE BATTLES','KENO','HI-LO','SNAKE','ITEM UPGRADER'].includes(s.game)){
            let o=s.bucket, detail='';
            if(s.game==='DICE'){const target=Math.min(99,Math.max(1,Number(value)||50));const over=req.body?.over!==false;const win=over?s.roll>target:s.roll<target; if(!win)o='LOSS';detail=`Rolled ${s.roll.toFixed(2)} • target ${target}`;}
            if(s.game==='LIMBO'){const target=Math.max(1.01,Number(value)||2); if(s.multiplier<target)o='LOSS';detail=`Round reached ${s.multiplier.toFixed(2)}×`}
            if(s.game==='COINFLIP'){const side=String(value||'HEADS').toUpperCase(); if(side!==s.side)o='LOSS';detail=`Coin landed ${s.side}`}
            if(s.game==='RUSSIAN ROULETTE'){const chamber=Number(value);if(chamber===s.chamber)o='LOSS';detail=`Chamber ${s.chamber} was loaded`}
            if(s.game==='DONUT ROULETTE'){const pocket=Number(value);const landed=Math.floor(fairUnit(fairRounds.get(s.roundId).serverSeed,s.roundId,0,321)*16);if(pocket!==landed)o='LOSS';detail=`Wheel landed on pocket ${landed+1}`}
            if(s.game==='WHEEL'){detail=`Wheel stopped at ${(s.pocket*100).toFixed(0)}%`}
            if(s.game==='PLINKO'){detail=`Ball bounced through ${s.path.map(x=>x?'R':'L').join('')}`}
            if(s.game==='CASES'){detail=`Case drop: ${s.drop>.85?'LEGENDARY':s.drop>.6?'EPIC':s.drop>.3?'RARE':'COMMON'}`}
            if(s.game==='STRIP MINE'){detail=s.drop>.72?'Diamond vein found':'The tunnel collapsed'}
            if(s.game==='CASE BATTLES'){detail=`Your case ${s.bucket==='WIN'?'outscored':'lost to'} the opponent`}
            if(s.game==='KENO'){const chosen=Array.isArray(value)?value.map(Number):[];const hits=chosen.filter(n=>s.draw.includes(n)).length;if(hits===0)o='LOSS';detail=`${hits} numbers hit`}
            if(s.game==='HI-LO'){const call=String(value||'HIGH').toUpperCase();const card=s.nextCard;const win=call==='HIGH'?card>=8:card<=6;if(!win)o='LOSS';detail=`Next card value ${card}`}
            if(s.game==='SNAKE'){s.moves++;s.score+=1;if(s.moves<3&&s.bucket==='LOSS')o='LOSS';detail=`Snake score ${s.score}`}
            if(s.game==='ITEM UPGRADER'){detail=s.drop>.65?'Upgrade succeeded':'Upgrade failed'}
            if(s.bucket==='WIN'&&o==='LOSS' && ['WHEEL','PLINKO','CASES','CASE BATTLES','STRIP MINE','ITEM UPGRADER'].includes(s.game))o='WIN';
            if(s.bucket==='TIE')o='TIE';
            return res.json(settleState(s,o,detail,o==='WIN'?s.bet*2:o==='TIE'?s.bet:0));
        }
        return res.status(400).json({error:'Unsupported game action.'});
    }catch(e){return res.status(400).json({error:e.message||'Game action failed.'});}
});

app.post('/api/game/cancel',(req,res)=>{const session=requireSession(req,res);if(!session)return;const id=String(req.body?.gameId||'');const s=activeGames.get(id);if(s&&s.sessionKey===session.key&&!s.finished){activeGames.delete(id);return res.json({success:true});}res.json({success:true});});

app.get('/api/wager-race',(req,res)=>{
    const totals=new Map();
    for(const t of (data.transactions||[])){
        if(t.type!=='game') continue;
        const username=String(t.username||'').trim();
        const wager=Number(t.wager);
        if(!username||!Number.isFinite(wager)||wager<=0) continue;
        const key=usernameKey(username);
        const row=totals.get(key)||{username,wagered:0,bets:0};
        row.wagered+=wager; row.bets+=1; totals.set(key,row);
    }
    const leaderboard=[...totals.values()].sort((a,b)=>b.wagered-a.wagered||b.bets-a.bets||a.username.localeCompare(b.username)).slice(0,50);
    res.json({leaderboard});
});

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        if(
            req.path.startsWith("/api/")
        ){

            return res.status(404).json({
                error:
                    "API endpoint not found."
            });
        }


        res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }
);


/* =========================================================
   START
========================================================= */

const server =
    app.listen(
        PORT,
        HOST,
        () => {

            console.log("");
            console.log(
                "========================================"
            );
            console.log(
                "        DONUTMINE SERVER ONLINE"
            );
            console.log(
                "========================================"
            );
            console.log(
                `Website: http://127.0.0.1:${PORT}`
            );
            console.log(
                `Receiver: ${RECEIVER}`
            );
            console.log(
                "Minecraft chat: BACKEND ONLY"
            );
            console.log(
                "Payment reader: ONLINE"
            );
            console.log(
                "Provably fair: ENABLED"
            );
            console.log(
                "========================================"
            );
            console.log("");

            startBot();
        }
    );