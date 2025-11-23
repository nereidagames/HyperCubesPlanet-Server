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
app.use(express.json({ limit: '10mb' }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

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

// --- DB INIT ---
app.get('/api/init-database', async (req, res) => {
  const providedKey = req.query.key;
  if (!process.env.INIT_DB_SECRET_KEY || providedKey !== process.env.INIT_DB_SECRET_KEY) {
    return res.status(403).send('Brak autoryzacji.');
  }
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, coins INTEGER DEFAULT 0 NOT NULL, current_skin_thumbnail TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS current_skin_thumbnail TEXT;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 0 NOT NULL;`);
    await pool.query(`CREATE TABLE IF NOT EXISTS friendships (id SERIAL PRIMARY KEY, user_id1 INTEGER REFERENCES users(id) NOT NULL, user_id2 INTEGER REFERENCES users(id) NOT NULL, status VARCHAR(20) DEFAULT 'pending', created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id1, user_id2));`);
    await pool.query(`CREATE TABLE IF NOT EXISTS skins (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`CREATE TABLE IF NOT EXISTS private_messages (id SERIAL PRIMARY KEY, sender_id INTEGER REFERENCES users(id) NOT NULL, recipient_id INTEGER REFERENCES users(id) NOT NULL, message_text TEXT NOT NULL, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
    res.status(200).send('Baza danych OK.');
  } catch (err) { res.status(500).send('Błąd: ' + err.message); }
});

// --- AUTH & API ---
// (Skrócone dla czytelności - logika taka sama jak w poprzednich wersjach)
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Brak danych.' });
  try {
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);
    await pool.query('INSERT INTO users (username, password_hash, coins) VALUES ($1, $2, 0)', [username, password_hash]);
    res.status(201).json({ message: 'Konto utworzone.' });
  } catch (err) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: 'Brak użytkownika.' });
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ message: 'Złe hasło.' });
    const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const coins = user.coins !== null ? user.coins : 0;
    res.json({ token, user: { id: user.id, username: user.username, coins: coins }, thumbnail: user.current_skin_thumbnail });
  } catch (err) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const result = await pool.query('SELECT id, username, coins, current_skin_thumbnail FROM users WHERE id = $1', [userId]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' });
        const u = result.rows[0];
        const coins = u.coins !== null ? u.coins : 0;
        res.json({ user: { id: u.id, username: u.username, coins: coins }, thumbnail: u.current_skin_thumbnail });
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});

app.post('/api/user/thumbnail', authenticateToken, async (req, res) => {
    const { thumbnail } = req.body;
    const userId = req.user.userId;
    try {
        await pool.query('UPDATE users SET current_skin_thumbnail = $1 WHERE id = $2', [thumbnail, userId]);
        const socketData = players.get(parseInt(userId));
        if (socketData) socketData.thumbnail = thumbnail;
        res.sendStatus(200);
    } catch (err) { res.sendStatus(500); }
});

// --- SKINY & ZNAJOMI (Bez zmian w logice API) ---
app.post('/api/skins', authenticateToken, async (req, res) => {
    const { name, blocks, thumbnail } = req.body;
    try {
        const result = await pool.query(`INSERT INTO skins (owner_id, name, blocks_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, name, JSON.stringify(blocks), thumbnail]);
        res.status(201).json({ message: 'Skin zapisany.', skinId: result.rows[0].id });
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.get('/api/skins/mine', authenticateToken, async (req, res) => {
    try { const result = await pool.query(`SELECT id, name, thumbnail, owner_id, created_at FROM skins WHERE owner_id = $1 ORDER BY created_at DESC`, [req.user.userId]); res.json(result.rows); } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.get('/api/skins/all', authenticateToken, async (req, res) => {
    try { const result = await pool.query(`SELECT s.id, s.name, s.thumbnail, s.owner_id, u.username as creator FROM skins s JOIN users u ON s.owner_id = u.id ORDER BY s.created_at DESC LIMIT 50`); res.json(result.rows); } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.get('/api/skins/:id', authenticateToken, async (req, res) => {
    try { const result = await pool.query(`SELECT blocks_data FROM skins WHERE id = $1`, [req.params.id]); if (result.rows.length === 0) return res.status(404).json({ message: 'Brak.' }); res.json(result.rows[0].blocks_data); } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const friendsQuery = await pool.query(`SELECT u.id, u.username, u.current_skin_thumbnail FROM friendships f JOIN users u ON u.id = (CASE WHEN f.user_id1 = $1 THEN f.user_id2 ELSE f.user_id1 END) WHERE (f.user_id1 = $1 OR f.user_id2 = $1) AND f.status = 'accepted'`, [userId]);
        const requestsQuery = await pool.query(`SELECT f.id as request_id, u.id as user_id, u.username, u.current_skin_thumbnail FROM friendships f JOIN users u ON u.id = f.user_id1 WHERE f.user_id2 = $1 AND f.status = 'pending'`, [userId]);
        const friends = friendsQuery.rows.map(f => ({ ...f, isOnline: players.has(f.id) }));
        res.json({ friends, requests: requestsQuery.rows });
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.post('/api/friends/search', authenticateToken, async (req, res) => {
    try { const result = await pool.query(`SELECT id, username, current_skin_thumbnail FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 10`, [`%${req.body.query}%`, req.user.userId]); res.json(result.rows); } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    const { targetUserId } = req.body; const userId = req.user.userId;
    if(userId === targetUserId) return res.status(400).json({message: "Error."});
    try {
        const check = await pool.query(`SELECT * FROM friendships WHERE (user_id1 = $1 AND user_id2 = $2) OR (user_id1 = $2 AND user_id2 = $1)`, [userId, targetUserId]);
        if (check.rows.length > 0) return res.status(400).json({ message: 'Już istnieje.' });
        await pool.query(`INSERT INTO friendships (user_id1, user_id2, status) VALUES ($1, $2, 'pending')`, [userId, targetUserId]);
        res.json({ message: 'Wysłano.' });
        const targetSocket = players.get(targetUserId);
        if (targetSocket && targetSocket.ws.readyState === 1) targetSocket.ws.send(JSON.stringify({ type: 'friendRequestReceived', from: req.user.username }));
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.post('/api/friends/accept', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`UPDATE friendships SET status = 'accepted' WHERE id = $1 AND user_id2 = $2 AND status = 'pending' RETURNING user_id1`, [req.body.requestId, req.user.userId]);
        if (result.rowCount === 0) return res.status(400).json({ message: 'Błąd.' });
        res.json({ message: 'Przyjęto.' });
        const senderSocket = players.get(result.rows[0].user_id1);
        if (senderSocket && senderSocket.ws.readyState === 1) {
            senderSocket.ws.send(JSON.stringify({ type: 'friendRequestAccepted', by: req.user.username }));
            senderSocket.ws.send(JSON.stringify({ type: 'friendStatusChange' }));
        }
        const mySocket = players.get(req.user.userId);
        if (mySocket) mySocket.ws.send(JSON.stringify({ type: 'friendStatusChange' }));
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.post('/api/coins/update', authenticateToken, async (req, res) => {
    try { const result = await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + $1 WHERE id = $2 RETURNING coins', [req.body.amount, req.user.userId]); res.json({ newBalance: result.rows[0].coins }); } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.get('/api/messages', authenticateToken, async (req, res) => {
    try { const r = await pool.query(`SELECT DISTINCT ON (other_user_id) other_user_id, other_username, message_text, created_at FROM (SELECT CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END as other_user_id, m.message_text, m.created_at FROM private_messages m WHERE m.sender_id = $1 OR m.recipient_id = $1 ORDER BY m.created_at DESC) AS sub JOIN users u ON u.id = sub.other_user_id GROUP BY other_user_id, other_username, message_text, created_at ORDER BY created_at DESC`, [req.user.userId]); res.json(r.rows); } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});
app.get('/api/messages/:username', authenticateToken, async (req, res) => {
    try {
        const ures = await pool.query('SELECT id FROM users WHERE username = $1', [req.params.username]);
        if (ures.rows.length === 0) return res.status(404).json({ message: 'Brak.' });
        const msgs = await pool.query(`SELECT m.id, m.sender_id, u.username as sender_username, m.message_text, m.created_at FROM private_messages m JOIN users u ON m.sender_id = u.id WHERE (sender_id = $1 AND recipient_id = $2) OR (sender_id = $2 AND recipient_id = $1) ORDER BY m.created_at ASC`, [req.user.userId, ures.rows[0].id]);
        res.json(msgs.rows);
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});

// --- WEBSOCKET & BROADCAST ---

function broadcast(message, excludePlayerId = null) {
  const messageStr = JSON.stringify(message);
  players.forEach((playerData, playerId) => {
    // WAŻNE: Sprawdzamy ID (int) i readyState === 1
    if (playerId !== excludePlayerId && playerData.ws.readyState === 1) {
      playerData.ws.send(messageStr);
    }
  });
}

function spawnCoin() {
    if (currentCoin) return;
    const x = (Math.random() - 0.5) * 2 * MAP_BOUNDS;
    const z = (Math.random() - 0.5) * 2 * MAP_BOUNDS;
    currentCoin = { position: { x, y: 1, z } };
    broadcast({ type: 'coinSpawned', position: currentCoin.position });
    console.log(`Spawn monety: ${x.toFixed(1)}, ${z.toFixed(1)}`);
}

function notifyFriendsStatus(userId, isOnline) {
    (async () => {
        try {
            const friends = await pool.query(`SELECT user_id1, user_id2 FROM friendships WHERE (user_id1 = $1 OR user_id2 = $1) AND status = 'accepted'`, [userId]);
            friends.rows.forEach(row => {
                const friendId = row.user_id1 === userId ? row.user_id2 : row.user_id1;
                const friendSocket = players.get(friendId);
                if (friendSocket && friendSocket.ws.readyState === 1) {
                    friendSocket.ws.send(JSON.stringify({ type: 'friendStatusChange', friendId: userId, isOnline: isOnline }));
                }
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
        
        // KONWERSJA NA INT DLA PEWNOŚCI
        const playerId = parseInt(decoded.userId);
        const username = decoded.username;
        console.log(`Gracz ${username} (ID: ${playerId}) online.`);
        
        const startX = (Math.random() * 4) - 2;
        const startZ = (Math.random() * 4) - 2;

        players.set(playerId, { 
            ws, nickname: username, skinData: null, thumbnail: null, 
            position: { x: startX, y: 0.9, z: startZ }, quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 } 
        });

        notifyFriendsStatus(playerId, true);
        ws.send(JSON.stringify({ type: 'welcome', id: playerId, username: username }));
        
        const existingPlayers = [];
        players.forEach((pd, id) => { if (id !== playerId) existingPlayers.push({ id, nickname: pd.nickname, skinData: pd.skinData, position: pd.position, quaternion: pd.quaternion }); });
        ws.send(JSON.stringify({ type: 'playerList', players: existingPlayers }));
        
        if (currentCoin) ws.send(JSON.stringify({ type: 'coinSpawned', position: currentCoin.position }));

        ws.on('message', async (message) => {
            try {
                const data = JSON.parse(message);
                const currentPlayer = players.get(playerId);
                if (!currentPlayer) return;

                if (data.type === 'playerReady') {
                    currentPlayer.skinData = data.skinData;
                    players.get(playerId).skinData = data.skinData; 
                    broadcast({ type: 'playerJoined', id: playerId, nickname: currentPlayer.nickname, skinData: data.skinData, position: currentPlayer.position, quaternion: currentPlayer.quaternion }, playerId);
                }
                if (data.type === 'chatMessage') broadcast({ type: 'chatMessage', id: playerId, nickname: currentPlayer.nickname, text: data.text });
                
                if (data.type === 'playerMove') {
                    currentPlayer.position = data.position;
                    currentPlayer.quaternion = data.quaternion;
                    // Przesyłamy ID gracza, aby klienci wiedzieli, kogo ruszyć
                    broadcast({ type: 'playerMove', id: playerId, position: data.position, quaternion: data.quaternion }, playerId);
                }

                if (data.type === 'collectCoin') {
                    if (currentCoin) {
                        // Brak sprawdzania dystansu dla lepszej responsywności
                        currentCoin = null;
                        broadcast({ type: 'coinCollected' });
                        try { 
                            const result = await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + $1 WHERE id = $2 RETURNING coins', [200, playerId]); 
                            if(result.rows.length > 0) ws.send(JSON.stringify({ type: 'updateBalance', newBalance: result.rows[0].coins }));
                        } catch(e) {}
                        setTimeout(spawnCoin, 5000);
                    }
                }
            } catch (error) {}
        });
        ws.on('close', () => {
            players.delete(playerId);
            notifyFriendsStatus(playerId, false);
            broadcast({ type: 'playerLeft', id: playerId });
        });
    });
});

server.listen(port, () => {
  console.log(`Serwer nasłuchuje na porcie ${port}`);
  setTimeout(spawnCoin, 10000);
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (RENDER_URL) setInterval(() => { https.get(RENDER_URL).on('error', () => {}); }, 840000);
});