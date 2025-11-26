require('dotenv').config();

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const https = require('https');

const port = process.env.PORT || 10000;
const app = express();

const corsOptions = { origin: 'https://nereidagames.github.io' };
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' })); 

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const players = new Map();
let currentCoin = null;
const MAP_BOUNDS = 30;

// --- CACHE MAPY NEXUSA ---
let nexusBlocksCache = [];

async function loadNexusMapToMemory() {
    try {
        const result = await pool.query('SELECT map_data FROM nexus_map WHERE id = 1');
        if (result.rows.length > 0) {
            nexusBlocksCache = result.rows[0].map_data || [];
            console.log(`[Server] Załadowano mapę Nexusa: ${nexusBlocksCache.length} bloków.`);
        } else {
            nexusBlocksCache = [];
        }
    } catch (e) {
        console.error("[Server] Błąd ładowania mapy:", e);
        nexusBlocksCache = [];
    }
}

// --- SPAWN LOGIC ---
function getSmartSpawnPosition(targetX, targetZ, isPlayer = false) {
    let highestBlock = null;
    let highestY = -1000;
    const searchRadius = 0.6;

    for (const block of nexusBlocksCache) {
        if (Math.abs(targetX - block.x) < searchRadius && Math.abs(targetZ - block.z) < searchRadius) {
            if (block.y > highestY) {
                highestY = block.y;
                highestBlock = block;
            }
        }
    }

    if (highestBlock) {
        const offset = isPlayer ? 20.0 : 0.8; 
        return { x: highestBlock.x, y: highestY + 0.5 + offset, z: highestBlock.z };
    } else {
        return { x: targetX, y: isPlayer ? 30.0 : 1.0, z: targetZ };
    }
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const interval = setInterval(function ping() {
  wss.clients.forEach(function each(ws) {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

app.get('/', (req, res) => res.send('Serwer HyperCubesPlanet działa!'));

// --- INIT DB ---
app.get('/api/init-database', async (req, res) => {
  const providedKey = req.query.key;
  if (!process.env.INIT_DB_SECRET_KEY || providedKey !== process.env.INIT_DB_SECRET_KEY) {
    return res.status(403).send('Brak autoryzacji.');
  }
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, coins INTEGER DEFAULT 0 NOT NULL, current_skin_thumbnail TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS current_skin_thumbnail TEXT;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 0 NOT NULL;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS owned_blocks JSONB DEFAULT '["Ziemia"]'::jsonb;`);
    await pool.query(`CREATE TABLE IF NOT EXISTS friendships (id SERIAL PRIMARY KEY, user_id1 INTEGER REFERENCES users(id) NOT NULL, user_id2 INTEGER REFERENCES users(id) NOT NULL, status VARCHAR(20) DEFAULT 'pending', created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id1, user_id2));`);
    await pool.query(`CREATE TABLE IF NOT EXISTS skins (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`CREATE TABLE IF NOT EXISTS worlds (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, world_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`CREATE TABLE IF NOT EXISTS private_messages (id SERIAL PRIMARY KEY, sender_id INTEGER REFERENCES users(id) NOT NULL, recipient_id INTEGER REFERENCES users(id) NOT NULL, message_text TEXT NOT NULL, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`CREATE TABLE IF NOT EXISTS nexus_map (id INTEGER PRIMARY KEY CHECK (id = 1), map_data JSONB);`);
    
    await loadNexusMapToMemory();

    res.status(200).send('Baza danych zaktualizowana.');
  } catch (err) {
    res.status(500).send('Błąd serwera: ' + err.message);
  }
});

// --- HELPER: Parse owned blocks ---
function parseOwnedBlocks(dbValue) {
    if (!dbValue) return ["Ziemia"];
    if (Array.isArray(dbValue)) return dbValue;
    if (typeof dbValue === 'string') {
        try { return JSON.parse(dbValue); } catch (e) { return ["Ziemia"]; }
    }
    return ["Ziemia"];
}

// --- API ENDPOINTS ---

app.get('/api/nexus', async (req, res) => {
    try {
        if (nexusBlocksCache.length > 0) res.json(nexusBlocksCache);
        else {
            const result = await pool.query('SELECT map_data FROM nexus_map WHERE id = 1');
            if (result.rows.length > 0) { nexusBlocksCache = result.rows[0].map_data; res.json(result.rows[0].map_data); }
            else res.status(404).json({ message: 'Brak mapy' });
        }
    } catch (e) { res.status(500).json({ message: 'Błąd serwera' }); }
});

app.post('/api/nexus', authenticateToken, async (req, res) => {
    const allowedAdmins = ['admin', 'nixox2']; 
    if (!allowedAdmins.includes(req.user.username)) return res.status(403).json({ message: "Brak uprawnień!" });
    const { blocks } = req.body;
    if (!blocks) return res.status(400).json({ message: "Brak danych." });
    try {
        await pool.query(`INSERT INTO nexus_map (id, map_data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET map_data = $1`, [JSON.stringify(blocks)]);
        nexusBlocksCache = blocks;
        res.json({ message: 'Nexus zaktualizowany!' });
    } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Brak danych.' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(`INSERT INTO users (username, password_hash, coins, owned_blocks) VALUES ($1, $2, 0, '["Ziemia"]'::jsonb)`, [username, hash]);
    res.status(201).json({ message: 'Utworzono.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const u = r.rows[0];
    if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ message: 'Błąd logowania.' });
    const token = jwt.sign({ userId: u.id, username: u.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    // Zawsze zwracaj tablicę
    const blocks = parseOwnedBlocks(u.owned_blocks);
    
    res.json({ 
        token, 
        user: { id: u.id, username: u.username, coins: u.coins || 0, ownedBlocks: blocks }, 
        thumbnail: u.current_skin_thumbnail 
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query('SELECT id, username, coins, current_skin_thumbnail, owned_blocks FROM users WHERE id = $1', [req.user.userId]);
        if (r.rows.length === 0) return res.status(404).send();
        const u = r.rows[0];
        const blocks = parseOwnedBlocks(u.owned_blocks);
        res.json({ 
            user: { id: u.id, username: u.username, coins: u.coins || 0, ownedBlocks: blocks }, 
            thumbnail: u.current_skin_thumbnail 
        });
    } catch (e) { res.status(500).json({ message: e.message }); }
});

// --- SKLEP: KUPNO BLOKU (POPRAWIONE) ---
app.post('/api/shop/buy', authenticateToken, async (req, res) => {
    const { blockName, cost } = req.body;
    const userId = req.user.userId;

    try {
        const userResult = await pool.query('SELECT coins, owned_blocks FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ message: "Użytkownik nie istnieje" });
        
        const user = userResult.rows[0];
        const currentCoins = user.coins || 0;
        
        // 1. Bezpieczne parsowanie posiadanych bloków
        let ownedBlocks = parseOwnedBlocks(user.owned_blocks);

        // 2. Walidacja
        if (ownedBlocks.includes(blockName)) {
            return res.status(400).json({ message: "Już posiadasz ten blok!" });
        }
        if (currentCoins < cost) {
            return res.status(400).json({ message: "Za mało monet!" });
        }

        // 3. Aktualizacja
        ownedBlocks.push(blockName);
        const newBalance = currentCoins - cost;

        // Zapisujemy jako JSON string, żeby Postgres na pewno to zrozumiał
        await pool.query(
            'UPDATE users SET coins = $1, owned_blocks = $2 WHERE id = $3',
            [newBalance, JSON.stringify(ownedBlocks), userId]
        );

        // 4. Zwracamy czystą tablicę do klienta
        res.json({ 
            success: true, 
            newBalance: newBalance, 
            ownedBlocks: ownedBlocks 
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Błąd transakcji serwera." });
    }
});

// ... (Reszta API bez zmian: coins/update, skins, worlds, friends, messages) ...
app.post('/api/user/thumbnail', authenticateToken, async (req, res) => { try { await pool.query('UPDATE users SET current_skin_thumbnail = $1 WHERE id = $2', [req.body.thumbnail, req.user.userId]); const p = players.get(parseInt(req.user.userId)); if (p) p.thumbnail = req.body.thumbnail; res.sendStatus(200); } catch (e) { res.sendStatus(500); } });
app.post('/api/skins', authenticateToken, async (req, res) => { try { const r = await pool.query(`INSERT INTO skins (owner_id, name, blocks_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, req.body.name, JSON.stringify(req.body.blocks), req.body.thumbnail]); res.status(201).json({ message: 'Zapisano.', skinId: r.rows[0].id }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/skins/mine', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT id, name, thumbnail, owner_id, created_at FROM skins WHERE owner_id = $1 ORDER BY created_at DESC`, [req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/skins/all', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT s.id, s.name, s.thumbnail, s.owner_id, u.username as creator FROM skins s JOIN users u ON s.owner_id = u.id ORDER BY s.created_at DESC LIMIT 50`); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/skins/:id', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT blocks_data FROM skins WHERE id = $1`, [req.params.id]); if (r.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' }); res.json(r.rows[0].blocks_data); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/worlds', authenticateToken, async (req, res) => { const { name, world_data, thumbnail } = req.body; if (!name || !world_data) return res.status(400).json({ message: "Brak danych." }); try { const r = await pool.query(`INSERT INTO worlds (owner_id, name, world_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, name, JSON.stringify(world_data), thumbnail]); res.status(201).json({ message: 'Zapisano.', worldId: r.rows[0].id }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/worlds/all', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT w.id, w.name, w.thumbnail, w.owner_id, u.username as creator FROM worlds w JOIN users u ON w.owner_id = u.id ORDER BY w.created_at DESC LIMIT 50`); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/worlds/:id', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT world_data FROM worlds WHERE id = $1`, [req.params.id]); if (r.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' }); res.json(r.rows[0].world_data); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/friends', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT u.id, u.username, u.current_skin_thumbnail FROM friendships f JOIN users u ON u.id = (CASE WHEN f.user_id1 = $1 THEN f.user_id2 ELSE f.user_id1 END) WHERE (f.user_id1 = $1 OR f.user_id2 = $1) AND f.status = 'accepted'`, [req.user.userId]); const reqs = await pool.query(`SELECT f.id as request_id, u.id as user_id, u.username, u.current_skin_thumbnail FROM friendships f JOIN users u ON u.id = f.user_id1 WHERE f.user_id2 = $1 AND f.status = 'pending'`, [req.user.userId]); const friends = r.rows.map(f => ({ ...f, isOnline: players.has(f.id) })); res.json({ friends, requests: reqs.rows }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/friends/search', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT id, username, current_skin_thumbnail FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 10`, [`%${req.body.query}%`, req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/friends/request', authenticateToken, async (req, res) => { const { targetUserId } = req.body; if(req.user.userId === targetUserId) return res.status(400).json({message: "Błąd."}); try { const chk = await pool.query(`SELECT * FROM friendships WHERE (user_id1=$1 AND user_id2=$2) OR (user_id1=$2 AND user_id2=$1)`, [req.user.userId, targetUserId]); if(chk.rows.length>0) return res.status(400).json({ message: 'Już istnieje.' }); await pool.query(`INSERT INTO friendships (user_id1, user_id2, status) VALUES ($1, $2, 'pending')`, [req.user.userId, targetUserId]); res.json({ message: 'Wysłano.' }); const t = players.get(parseInt(targetUserId)); if(t && t.ws.readyState===1) t.ws.send(JSON.stringify({ type: 'friendRequestReceived', from: req.user.username })); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/friends/accept', authenticateToken, async (req, res) => { try { const r = await pool.query(`UPDATE friendships SET status = 'accepted' WHERE id = $1 AND user_id2 = $2 AND status = 'pending' RETURNING user_id1`, [req.body.requestId, req.user.userId]); if(r.rowCount===0) return res.status(400).json({ message: 'Błąd.' }); res.json({ message: 'Przyjęto.' }); const sid = r.rows[0].user_id1; const ss = players.get(sid); if(ss && ss.ws.readyState===1){ ss.ws.send(JSON.stringify({ type: 'friendRequestAccepted', by: req.user.username })); ss.ws.send(JSON.stringify({ type: 'friendStatusChange' })); } const ms = players.get(parseInt(req.user.userId)); if(ms) ms.ws.send(JSON.stringify({ type: 'friendStatusChange' })); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/coins/update', authenticateToken, async (req, res) => { try { const r = await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + $1 WHERE id = $2 RETURNING coins', [req.body.amount, req.user.userId]); res.json({ newBalance: r.rows[0].coins }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/messages', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT DISTINCT ON (other_user_id) other_user_id, other_username, message_text, created_at FROM (SELECT CASE WHEN sender_id=$1 THEN recipient_id ELSE sender_id END as other_user_id, m.message_text, m.created_at FROM private_messages m WHERE m.sender_id=$1 OR m.recipient_id=$1 ORDER BY m.created_at DESC) AS sub JOIN users u ON u.id = sub.other_user_id GROUP BY other_user_id, other_username, message_text, created_at ORDER BY created_at DESC`, [req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/messages/:username', authenticateToken, async (req, res) => { try { const u = await pool.query('SELECT id FROM users WHERE username = $1', [req.params.username]); if (u.rows.length === 0) return res.status(404).json({ message: 'Brak.' }); const m = await pool.query(`SELECT m.id, m.sender_id, u.username as sender_username, m.message_text, m.created_at FROM private_messages m JOIN users u ON m.sender_id = u.id WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1) ORDER BY m.created_at ASC`, [req.user.userId, u.rows[0].id]); res.json(m.rows); } catch (e) { res.status(500).json({ message: e.message }); } });

// --- WEBSOCKET ---
function broadcastToWorld(worldId, data, excludeId = null) { const msg = JSON.stringify(data); players.forEach((p, id) => { if (p.currentWorld === worldId && id !== excludeId && p.ws.readyState === 1) { p.ws.send(msg); } }); }
function spawnCoin() { if (currentCoin) return; const x = Math.floor((Math.random() - 0.5) * 2 * MAP_BOUNDS) + 0.5; const z = Math.floor((Math.random() - 0.5) * 2 * MAP_BOUNDS) + 0.5; const pos = getSmartSpawnPosition(x, z, false); currentCoin = { position: pos }; broadcastToWorld('nexus', { type: 'coinSpawned', position: currentCoin.position }); }
function notifyFriendsStatus(userId, isOnline) { (async () => { try { const r = await pool.query(`SELECT user_id1, user_id2 FROM friendships WHERE (user_id1=$1 OR user_id2=$1) AND status='accepted'`, [userId]); r.rows.forEach(row => { const fid = row.user_id1 === userId ? row.user_id2 : row.user_id1; const s = players.get(fid); if(s && s.ws.readyState===1) s.ws.send(JSON.stringify({ type: 'friendStatusChange' })); }); } catch (e) {} })(); }

wss.on('connection', (ws, req) => {
    ws.isAlive = true; ws.on('pong', () => { ws.isAlive = true; });
    const url = new URL(req.url, `http://${req.headers.host}`); const token = url.searchParams.get('token'); if (!token) { ws.close(1008); return; }
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) { ws.close(1008); return; }
        const playerId = parseInt(decoded.userId); const username = decoded.username; console.log(`[WS] ${username} online.`);
        const startX = Math.floor((Math.random() * 6) - 3) + 0.5; const startZ = Math.floor((Math.random() * 6) - 3) + 0.5; const pos = getSmartSpawnPosition(startX, startZ, true);
        players.set(playerId, { ws, id: playerId, nickname: username, skinData: null, thumbnail: null, position: pos, quaternion: { _x:0,_y:0,_z:0,_w:1 }, currentWorld: 'nexus' });
        notifyFriendsStatus(playerId, true);
        setTimeout(() => { if (ws.readyState === ws.OPEN) { ws.send(JSON.stringify({ type: 'welcome', id: playerId, username: username, position: pos })); const nexusPlayers = []; players.forEach((p, id) => { if (id !== playerId && p.currentWorld === 'nexus') { nexusPlayers.push({ id: p.id, nickname: p.nickname, skinData: p.skinData, position: p.position, quaternion: p.quaternion }); } }); ws.send(JSON.stringify({ type: 'playerList', players: nexusPlayers })); if (currentCoin) ws.send(JSON.stringify({ type: 'coinSpawned', position: currentCoin.position })); } }, 1500);
        ws.on('message', async (message) => {
            try {
                const data = JSON.parse(message); const p = players.get(playerId); if (!p) return;
                if (data.type === 'joinWorld') {
                    const oldWorld = p.currentWorld; const newWorld = data.worldId || 'nexus';
                    if (oldWorld !== newWorld) {
                        broadcastToWorld(oldWorld, { type: 'playerLeft', id: playerId }, playerId); p.currentWorld = newWorld;
                        if (newWorld === 'nexus') { p.position = getSmartSpawnPosition(0.5, 0.5, true); } else { p.position = { x: 0, y: 5, z: 0 }; }
                        const roomPlayers = []; players.forEach((other, oid) => { if (oid !== playerId && other.currentWorld === newWorld) { roomPlayers.push({ id: other.id, nickname: other.nickname, skinData: other.skinData, position: other.position, quaternion: other.quaternion }); } }); ws.send(JSON.stringify({ type: 'playerList', players: roomPlayers })); broadcastToWorld(newWorld, { type: 'playerJoined', id: playerId, nickname: username, skinData: p.skinData, position: p.position, quaternion: p.quaternion }, playerId); if (newWorld === 'nexus' && currentCoin) { ws.send(JSON.stringify({ type: 'coinSpawned', position: currentCoin.position })); }
                    } return;
                }
                if (data.type === 'playerReady') { p.skinData = data.skinData; broadcastToWorld(p.currentWorld, { type: 'playerJoined', id: playerId, nickname: username, skinData: data.skinData, position: p.position, quaternion: p.quaternion }, playerId); }
                if (data.type === 'chatMessage') { broadcastToWorld(p.currentWorld, { type: 'chatMessage', id: playerId, nickname: username, text: data.text }); }
                if (data.type === 'playerMove') { p.position = data.position; p.quaternion = data.quaternion; broadcastToWorld(p.currentWorld, { type: 'playerMove', id: playerId, position: data.position, quaternion: data.quaternion }, playerId); }
                if (data.type === 'collectCoin') { if (p.currentWorld === 'nexus' && currentCoin) { currentCoin = null; broadcastToWorld('nexus', { type: 'coinCollected' }); try { const r = await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + 200 WHERE id = $1 RETURNING coins', [playerId]); if(r.rows.length > 0) ws.send(JSON.stringify({ type: 'updateBalance', newBalance: r.rows[0].coins })); } catch(e) {} setTimeout(spawnCoin, 5000); } }
                if (data.type === 'sendPrivateMessage') { const { recipient: recipientName, text } = data; try { const r = await pool.query('SELECT id FROM users WHERE username = $1', [recipientName]); if(r.rows.length > 0) { const recipientId = r.rows[0].id; await pool.query('INSERT INTO private_messages (sender_id, recipient_id, message_text) VALUES ($1, $2, $3)', [playerId, recipientId, text]); ws.send(JSON.stringify({ type: 'privateMessageSent', recipient: recipientName, text })); const rp = players.get(recipientId); if(rp && rp.ws.readyState===1) rp.ws.send(JSON.stringify({ type: 'privateMessageReceived', sender: { id: playerId, nickname: username }, text })); } } catch(e) {} }
            } catch (e) {}
        });
        ws.on('close', () => { players.delete(playerId); notifyFriendsStatus(playerId, false); broadcastToWorld(players.get(playerId)?.currentWorld || 'nexus', { type: 'playerLeft', id: playerId }); });
    });
});

server.listen(port, () => { console.log(`Serwer: ${port}`); loadNexusMapToMemory(); setTimeout(spawnCoin, 10000); const RENDER_URL = process.env.RENDER_EXTERNAL_URL; if (RENDER_URL) setInterval(() => { https.get(RENDER_URL).on('error', () => {}); }, 840000); });