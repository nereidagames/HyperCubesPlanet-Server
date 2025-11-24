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
app.use(express.json({ limit: '50mb' })); // Limit dla dużych światów/zdjęć

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Pamięć serwera
// players: Map<id, { ws, id, nickname, skinData, thumbnail, position, quaternion, currentWorld }>
const players = new Map();
let currentCoin = null;
const MAP_BOUNDS = 30;

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

app.get('/', (req, res) => res.send('Serwer HyperCubesPlanet działa!'));

// --- ENDPOINTY HTTP (Baza, Auth, Skiny, Światy, Przyjaciele) ---
// (Te endpointy pozostają bez zmian logicznych, są potrzebne do działania gry)

app.get('/api/init-database', async (req, res) => {
  const providedKey = req.query.key;
  if (!process.env.INIT_DB_SECRET_KEY || providedKey !== process.env.INIT_DB_SECRET_KEY) return res.status(403).send('Brak autoryzacji.');
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, coins INTEGER DEFAULT 0 NOT NULL, current_skin_thumbnail TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS current_skin_thumbnail TEXT;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 0 NOT NULL;`);
    await pool.query(`CREATE TABLE IF NOT EXISTS friendships (id SERIAL PRIMARY KEY, user_id1 INTEGER REFERENCES users(id) NOT NULL, user_id2 INTEGER REFERENCES users(id) NOT NULL, status VARCHAR(20) DEFAULT 'pending', created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id1, user_id2));`);
    await pool.query(`CREATE TABLE IF NOT EXISTS skins (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`CREATE TABLE IF NOT EXISTS worlds (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, world_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`CREATE TABLE IF NOT EXISTS private_messages (id SERIAL PRIMARY KEY, sender_id INTEGER REFERENCES users(id) NOT NULL, recipient_id INTEGER REFERENCES users(id) NOT NULL, message_text TEXT NOT NULL, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    res.status(200).send('Baza danych OK.');
  } catch (err) { res.status(500).send('Błąd: ' + err.message); }
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Brak danych.' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash, coins) VALUES ($1, $2, 0)', [username, hash]);
    res.status(201).json({ message: 'Utworzono.' });
  } catch (e) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const u = r.rows[0];
    if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ message: 'Błąd logowania.' });
    const token = jwt.sign({ userId: u.id, username: u.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: u.id, username: u.username, coins: u.coins || 0 }, thumbnail: u.current_skin_thumbnail });
  } catch (e) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query('SELECT id, username, coins, current_skin_thumbnail FROM users WHERE id = $1', [req.user.userId]);
        if (r.rows.length === 0) return res.status(404).send();
        const u = r.rows[0];
        res.json({ user: { id: u.id, username: u.username, coins: u.coins || 0 }, thumbnail: u.current_skin_thumbnail });
    } catch (e) { res.status(500).send(); }
});

app.post('/api/user/thumbnail', authenticateToken, async (req, res) => {
    try {
        await pool.query('UPDATE users SET current_skin_thumbnail = $1 WHERE id = $2', [req.body.thumbnail, req.user.userId]);
        const p = players.get(parseInt(req.user.userId));
        if (p) p.thumbnail = req.body.thumbnail;
        res.sendStatus(200);
    } catch (e) { res.sendStatus(500); }
});

// SKINY
app.post('/api/skins', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query(`INSERT INTO skins (owner_id, name, blocks_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, req.body.name, JSON.stringify(req.body.blocks), req.body.thumbnail]);
        res.status(201).json({ message: 'Zapisano.', skinId: r.rows[0].id });
    } catch (e) { res.status(500).json({ message: 'Błąd.' }); }
});
app.get('/api/skins/mine', authenticateToken, async (req, res) => {
    try { const r = await pool.query(`SELECT id, name, thumbnail, owner_id, created_at FROM skins WHERE owner_id = $1 ORDER BY created_at DESC`, [req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).send(); }
});
app.get('/api/skins/all', authenticateToken, async (req, res) => {
    try { const r = await pool.query(`SELECT s.id, s.name, s.thumbnail, s.owner_id, u.username as creator FROM skins s JOIN users u ON s.owner_id = u.id ORDER BY s.created_at DESC LIMIT 50`); res.json(r.rows); } catch (e) { res.status(500).send(); }
});
app.get('/api/skins/:id', authenticateToken, async (req, res) => {
    try { const r = await pool.query(`SELECT blocks_data FROM skins WHERE id = $1`, [req.params.id]); if (r.rows.length === 0) return res.status(404).send(); res.json(r.rows[0].blocks_data); } catch (e) { res.status(500).send(); }
});

// ŚWIATY
app.post('/api/worlds', authenticateToken, async (req, res) => {
    const { name, world_data, thumbnail } = req.body;
    if (!name || !world_data) return res.status(400).json({ message: "Brak danych." });
    try {
        const r = await pool.query(`INSERT INTO worlds (owner_id, name, world_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, name, JSON.stringify(world_data), thumbnail]);
        res.status(201).json({ message: 'Zapisano.', worldId: r.rows[0].id });
    } catch (e) { res.status(500).json({ message: e.message }); }
});
app.get('/api/worlds/all', authenticateToken, async (req, res) => {
    try { const r = await pool.query(`SELECT w.id, w.name, w.thumbnail, w.owner_id, u.username as creator FROM worlds w JOIN users u ON w.owner_id = u.id ORDER BY w.created_at DESC LIMIT 50`); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); }
});
app.get('/api/worlds/:id', authenticateToken, async (req, res) => {
    try { const r = await pool.query(`SELECT world_data FROM worlds WHERE id = $1`, [req.params.id]); if (r.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' }); res.json(r.rows[0].world_data); } catch (e) { res.status(500).json({ message: e.message }); }
});

// ZNAJOMI
app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query(`SELECT u.id, u.username, u.current_skin_thumbnail FROM friendships f JOIN users u ON u.id = (CASE WHEN f.user_id1 = $1 THEN f.user_id2 ELSE f.user_id1 END) WHERE (f.user_id1 = $1 OR f.user_id2 = $1) AND f.status = 'accepted'`, [req.user.userId]);
        const reqs = await pool.query(`SELECT f.id as request_id, u.id as user_id, u.username, u.current_skin_thumbnail FROM friendships f JOIN users u ON u.id = f.user_id1 WHERE f.user_id2 = $1 AND f.status = 'pending'`, [req.user.userId]);
        const friends = r.rows.map(f => ({ ...f, isOnline: players.has(f.id) }));
        res.json({ friends, requests: reqs.rows });
    } catch (e) { res.status(500).send(); }
});
app.post('/api/friends/search', authenticateToken, async (req, res) => {
    try { const r = await pool.query(`SELECT id, username, current_skin_thumbnail FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 10`, [`%${req.body.query}%`, req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).send(); }
});
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    const { targetUserId } = req.body;
    if(req.user.userId === targetUserId) return res.status(400).json({message: "Błąd."});
    try {
        const chk = await pool.query(`SELECT * FROM friendships WHERE (user_id1=$1 AND user_id2=$2) OR (user_id1=$2 AND user_id2=$1)`, [req.user.userId, targetUserId]);
        if(chk.rows.length>0) return res.status(400).json({ message: 'Już istnieje.' });
        await pool.query(`INSERT INTO friendships (user_id1, user_id2, status) VALUES ($1, $2, 'pending')`, [req.user.userId, targetUserId]);
        res.json({ message: 'Wysłano.' });
        const t = players.get(parseInt(targetUserId)); if(t && t.ws.readyState===1) t.ws.send(JSON.stringify({ type: 'friendRequestReceived', from: req.user.username }));
    } catch (e) { res.status(500).send(); }
});
app.post('/api/friends/accept', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query(`UPDATE friendships SET status='accepted' WHERE id=$1 AND user_id2=$2 AND status='pending' RETURNING user_id1`, [req.body.requestId, req.user.userId]);
        if(r.rowCount===0) return res.status(400).json({ message: 'Błąd.' });
        res.json({ message: 'Przyjęto.' });
        const sid = r.rows[0].user_id1;
        const ss = players.get(sid); if(ss && ss.ws.readyState===1){ ss.ws.send(JSON.stringify({ type: 'friendRequestAccepted', by: req.user.username })); ss.ws.send(JSON.stringify({ type: 'friendStatusChange' })); }
        const ms = players.get(parseInt(req.user.userId)); if(ms) ms.ws.send(JSON.stringify({ type: 'friendStatusChange' }));
    } catch (e) { res.status(500).send(); }
});

// --- CORE MULTIPLAYER (POKOJE) ---

// Funkcja wysyłająca wiadomość tylko do graczy w danym świecie
function broadcastToWorld(worldId, data, excludeId = null) {
    const msg = JSON.stringify(data);
    players.forEach((p, id) => {
        // Warunek: ten sam świat ORAZ nie nadawca ORAZ połączenie aktywne
        if (p.currentWorld === worldId && id !== excludeId && p.ws.readyState === 1) {
            p.ws.send(msg);
        }
    });
}

function spawnCoin() {
    if (currentCoin) return;
    const x = (Math.random() - 0.5) * 2 * MAP_BOUNDS;
    const z = (Math.random() - 0.5) * 2 * MAP_BOUNDS;
    currentCoin = { position: { x, y: 1, z } };
    // Monety spawnują się TYLKO w Nexusie ('nexus')
    broadcastToWorld('nexus', { type: 'coinSpawned', position: currentCoin.position });
}

function notifyFriendsStatus(userId, isOnline) {
    (async () => {
        try {
            const r = await pool.query(`SELECT user_id1, user_id2 FROM friendships WHERE (user_id1=$1 OR user_id2=$1) AND status='accepted'`, [userId]);
            r.rows.forEach(row => {
                const fid = row.user_id1 === userId ? row.user_id2 : row.user_id1;
                const s = players.get(fid);
                if(s && s.ws.readyState===1) s.ws.send(JSON.stringify({ type: 'friendStatusChange' }));
            });
        } catch (e) {}
    })();
}

wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    if (!token) { ws.close(1008); return; }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) { ws.close(1008); return; }
        const playerId = parseInt(decoded.userId);
        const username = decoded.username;
        console.log(`[WS] ${username} online.`);
        
        const startX = (Math.random() * 4) - 2;
        const startZ = (Math.random() * 4) - 2;

        // INICJALIZACJA GRACZA W NEXUSIE
        players.set(playerId, { 
            ws, id: playerId, nickname: username, 
            skinData: null, thumbnail: null, 
            position: { x: startX, y: 0.9, z: startZ }, 
            quaternion: { _x:0,_y:0,_z:0,_w:1 },
            currentWorld: 'nexus' // Domyślny świat
        });

        notifyFriendsStatus(playerId, true);
        ws.send(JSON.stringify({ type: 'welcome', id: playerId, username: username }));

        // Wyślij listę graczy tylko z Nexusa
        const nexusPlayers = [];
        players.forEach((p, id) => { 
            if (id !== playerId && p.currentWorld === 'nexus') {
                nexusPlayers.push({ id: p.id, nickname: p.nickname, skinData: p.skinData, position: p.position, quaternion: p.quaternion }); 
            }
        });
        ws.send(JSON.stringify({ type: 'playerList', players: nexusPlayers }));
        
        if (currentCoin) ws.send(JSON.stringify({ type: 'coinSpawned', position: currentCoin.position }));

        ws.on('message', async (message) => {
            try {
                const data = JSON.parse(message);
                const p = players.get(playerId);
                if (!p) return;

                // 1. Zmiana Świata (Wejście do pokoju)
                if (data.type === 'joinWorld') {
                    const oldWorld = p.currentWorld;
                    const newWorld = data.worldId || 'nexus'; // ID świata lub 'nexus'
                    
                    if (oldWorld !== newWorld) {
                        // Powiadom stary świat o wyjściu
                        broadcastToWorld(oldWorld, { type: 'playerLeft', id: playerId }, playerId);
                        
                        // Zaktualizuj stan
                        p.currentWorld = newWorld;
                        // Reset pozycji przy wejściu (opcjonalne, ale bezpieczne)
                        p.position = { x: 0, y: 5, z: 0 }; 
                        
                        // Pobierz listę graczy z NOWEGO świata
                        const roomPlayers = [];
                        players.forEach((other, oid) => {
                            if (oid !== playerId && other.currentWorld === newWorld) {
                                roomPlayers.push({ 
                                    id: other.id, nickname: other.nickname, 
                                    skinData: other.skinData, 
                                    position: other.position, quaternion: other.quaternion 
                                });
                            }
                        });
                        
                        // Wyślij graczowi nową listę (resetuje jego widok innych)
                        ws.send(JSON.stringify({ type: 'playerList', players: roomPlayers }));
                        
                        // Powiadom nowy świat o przyjściu (z pełnymi danymi skina!)
                        broadcastToWorld(newWorld, { 
                            type: 'playerJoined', 
                            id: playerId, 
                            nickname: username, 
                            skinData: p.skinData, // Ważne: wysyłamy zapamiętany skin
                            position: p.position, 
                            quaternion: p.quaternion 
                        }, playerId);

                        // Obsługa monet (tylko w Nexusie)
                        if (newWorld === 'nexus' && currentCoin) {
                            ws.send(JSON.stringify({ type: 'coinSpawned', position: currentCoin.position }));
                        }
                    }
                    return;
                }

                // 2. Inicjalizacja skina (po wejściu do gry)
                if (data.type === 'mySkin') {
                    p.skinData = data.skinData;
                    // Rozgłoś TYLKO w obecnym świecie (Nexusie na starcie)
                    broadcastToWorld(p.currentWorld, { type: 'playerJoined', id: playerId, nickname: username, skinData: data.skinData, position: p.position, quaternion: p.quaternion }, playerId);
                }

                // 3. Czat (lokalny dla świata)
                if (data.type === 'chatMessage') {
                    broadcastToWorld(p.currentWorld, { type: 'chatMessage', id: playerId, nickname: username, text: data.text });
                }
                
                // 4. Ruch (lokalny dla świata)
                if (data.type === 'playerMove') {
                    p.position = data.position;
                    p.quaternion = data.quaternion;
                    broadcastToWorld(p.currentWorld, { type: 'playerMove', id: playerId, position: data.position, quaternion: data.quaternion }, playerId);
                }

                // 5. Monety (Tylko w Nexusie)
                if (data.type === 'collectCoin') {
                    if (p.currentWorld === 'nexus' && currentCoin) {
                        currentCoin = null;
                        broadcastToWorld('nexus', { type: 'coinCollected' });
                        try { 
                            const r = await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + 200 WHERE id = $1 RETURNING coins', [playerId]); 
                            if(r.rows.length > 0) ws.send(JSON.stringify({ type: 'updateBalance', newBalance: r.rows[0].coins }));
                        } catch(e) {}
                        setTimeout(spawnCoin, 5000);
                    }
                }
                
                // 6. Prywatne (Globalne - nie zależy od świata)
                if (data.type === 'sendPrivateMessage') {
                    // (Logika obsługiwana przez HTTP dla wysyłania, ale tutaj można dodać realtime notification)
                }

            } catch (e) {}
        });

        ws.on('close', () => {
            players.delete(playerId);
            notifyFriendsStatus(playerId, false);
            // Poinformuj tylko świat, w którym był gracz
            broadcastToWorld(players.get(playerId)?.currentWorld || 'nexus', { type: 'playerLeft', id: playerId });
        });
    });
});

server.listen(port, () => {
  console.log(`Serwer: ${port}`);
  setTimeout(spawnCoin, 10000);
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (RENDER_URL) setInterval(() => { https.get(RENDER_URL).on('error', () => {}); }, 840000);
});