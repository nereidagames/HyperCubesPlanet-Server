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

// --- INICJALIZACJA BAZY ---
app.get('/api/init-database', async (req, res) => {
  const providedKey = req.query.key;
  if (!process.env.INIT_DB_SECRET_KEY || providedKey !== process.env.INIT_DB_SECRET_KEY) {
    return res.status(403).send('Brak autoryzacji.');
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(100) NOT NULL,
        coins INTEGER DEFAULT 0 NOT NULL,
        current_skin_thumbnail TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS current_skin_thumbnail TEXT;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 0 NOT NULL;`);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS friendships (
        id SERIAL PRIMARY KEY,
        user_id1 INTEGER REFERENCES users(id) NOT NULL,
        user_id2 INTEGER REFERENCES users(id) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id1, user_id2)
      );
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS skins (
        id SERIAL PRIMARY KEY,
        owner_id INTEGER REFERENCES users(id) NOT NULL,
        name VARCHAR(100) NOT NULL,
        thumbnail TEXT,
        blocks_data JSONB NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS private_messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id) NOT NULL,
        recipient_id INTEGER REFERENCES users(id) NOT NULL,
        message_text TEXT NOT NULL,
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    res.status(200).send('Baza danych zaktualizowana.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Błąd serwera: ' + err.message);
  }
});

// --- AUTH ---
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Brak danych.' });
  try {
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);
    const newUser = await pool.query(
      'INSERT INTO users (username, password_hash, coins) VALUES ($1, $2, 0) RETURNING id, username',
      [username, password_hash]
    );
    res.status(201).json({ user: newUser.rows[0], message: 'Konto utworzone.' });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ message: 'Nazwa zajęta.' });
    res.status(500).json({ message: 'Błąd serwera.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: 'Brak użytkownika.' });
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ message: 'Złe hasło.' });
    const payload = { userId: user.id, username: user.username };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, coins: user.coins || 0 }, thumbnail: user.current_skin_thumbnail });
  } catch (err) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const result = await pool.query('SELECT id, username, coins, current_skin_thumbnail FROM users WHERE id = $1', [userId]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' });
        const u = result.rows[0];
        res.json({ 
            user: { id: u.id, username: u.username, coins: u.coins || 0 }, 
            thumbnail: u.current_skin_thumbnail 
        });
    } catch (err) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.post('/api/user/thumbnail', authenticateToken, async (req, res) => {
    const { thumbnail } = req.body;
    const userId = req.user.userId;
    try {
        await pool.query('UPDATE users SET current_skin_thumbnail = $1 WHERE id = $2', [thumbnail, userId]);
        const socketData = players.get(userId);
        if (socketData) socketData.thumbnail = thumbnail;
        res.sendStatus(200);
    } catch (err) { console.error(err); res.sendStatus(500); }
});

// --- SKINY ---

app.post('/api/skins', authenticateToken, async (req, res) => {
    const { name, blocks, thumbnail } = req.body;
    const userId = req.user.userId;
    if (!name || !blocks) return res.status(400).json({ message: 'Brak danych.' });
    try {
        const result = await pool.query(
            `INSERT INTO skins (owner_id, name, blocks_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`,
            [userId, name, JSON.stringify(blocks), thumbnail]
        );
        res.status(201).json({ message: 'Skin zapisany.', skinId: result.rows[0].id });
    } catch (err) { res.status(500).json({ message: 'Błąd zapisu.' }); }
});

app.get('/api/skins/mine', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const result = await pool.query(
            `SELECT id, name, thumbnail, owner_id, created_at FROM skins WHERE owner_id = $1 ORDER BY created_at DESC`,
            [userId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.get('/api/skins/all', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT s.id, s.name, s.thumbnail, s.owner_id, u.username as creator 
             FROM skins s 
             JOIN users u ON s.owner_id = u.id 
             ORDER BY s.created_at DESC LIMIT 50`
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.get('/api/skins/:id', authenticateToken, async (req, res) => {
    const skinId = req.params.id;
    try {
        const result = await pool.query(`SELECT blocks_data FROM skins WHERE id = $1`, [skinId]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' });
        res.json(result.rows[0].blocks_data);
    } catch (err) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

// --- ZNAJOMI ---

app.get('/api/friends', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const friendsQuery = await pool.query(
            `SELECT u.id, u.username, u.current_skin_thumbnail
             FROM friendships f
             JOIN users u ON (
                (f.user_id1 = $1 AND u.id = f.user_id2) OR 
                (f.user_id2 = $1 AND u.id = f.user_id1)
             )
             WHERE (f.user_id1 = $1 OR f.user_id2 = $1) AND f.status = 'accepted'`,
            [userId]
        );
        const requestsQuery = await pool.query(
            `SELECT f.id as request_id, u.id as user_id, u.username, u.current_skin_thumbnail
             FROM friendships f JOIN users u ON u.id = f.user_id1 WHERE f.user_id2 = $1 AND f.status = 'pending'`, [userId]
        );
        const friends = friendsQuery.rows.map(f => ({ ...f, isOnline: players.has(f.id) }));
        res.json({ friends, requests: requestsQuery.rows });
    } catch (err) { res.status(500).json({ message: 'Błąd listy.' }); }
});

app.post('/api/friends/search', authenticateToken, async (req, res) => {
    const { query } = req.body;
    const userId = req.user.userId;
    try {
        const result = await pool.query(
            `SELECT id, username, current_skin_thumbnail FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 10`,
            [`%${query}%`, userId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ message: 'Błąd szukania.' }); }
});

app.post('/api/friends/request', authenticateToken, async (req, res) => {
    const { targetUserId } = req.body;
    const userId = req.user.userId;
    if(userId === targetUserId) return res.status(400).json({message: "Nie możesz dodać siebie."});
    try {
        const check = await pool.query(`SELECT * FROM friendships WHERE (user_id1 = $1 AND user_id2 = $2) OR (user_id1 = $2 AND user_id2 = $1)`, [userId, targetUserId]);
        if (check.rows.length > 0) return res.status(400).json({ message: 'Zaproszenie już istnieje.' });
        await pool.query(`INSERT INTO friendships (user_id1, user_id2, status) VALUES ($1, $2, 'pending')`, [userId, targetUserId]);
        res.json({ message: 'Wysłano zaproszenie.' });
        const targetSocket = players.get(targetUserId);
        if (targetSocket && targetSocket.ws.readyState === 1) targetSocket.ws.send(JSON.stringify({ type: 'friendRequestReceived', from: req.user.username }));
    } catch (err) { res.status(500).json({ message: 'Błąd bazy.' }); }
});

app.post('/api/friends/accept', authenticateToken, async (req, res) => {
    const { requestId } = req.body;
    const userId = req.user.userId;
    try {
        const result = await pool.query(`UPDATE friendships SET status = 'accepted' WHERE id = $1 AND user_id2 = $2 AND status = 'pending' RETURNING user_id1`, [requestId, userId]);
        if (result.rowCount === 0) return res.status(400).json({ message: 'Nie znaleziono.' });
        res.json({ message: 'Zaproszenie przyjęte.' });
        const senderId = result.rows[0].user_id1;
        const senderSocket = players.get(senderId);
        if (senderSocket && senderSocket.ws.readyState === 1) {
            senderSocket.ws.send(JSON.stringify({ type: 'friendRequestAccepted', by: req.user.username }));
            senderSocket.ws.send(JSON.stringify({ type: 'friendStatusChange' }));
        }
        const mySocket = players.get(userId);
        if (mySocket) mySocket.ws.send(JSON.stringify({ type: 'friendStatusChange' }));
    } catch (err) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

// --- INNE ---

app.post('/api/coins/update', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const userId = req.user.userId;
    try {
        const result = await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + $1 WHERE id = $2 RETURNING coins', [amount, userId]);
        res.json({ newBalance: result.rows[0].coins });
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});

app.get('/api/messages', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const result = await pool.query(
            `SELECT DISTINCT ON (other_user_id) other_user_id, other_username, message_text, created_at
             FROM (
                SELECT CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END as other_user_id, m.message_text, m.created_at
                FROM private_messages m WHERE m.sender_id = $1 OR m.recipient_id = $1 ORDER BY m.created_at DESC
             ) AS sub JOIN users u ON u.id = sub.other_user_id GROUP BY other_user_id, other_username, message_text, created_at ORDER BY created_at DESC`, [userId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});

app.get('/api/messages/:username', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const otherUsername = req.params.username;
    try {
        const otherUserResult = await pool.query('SELECT id FROM users WHERE username = $1', [otherUsername]);
        if (otherUserResult.rows.length === 0) return res.status(404).json({ message: 'Brak usera.' });
        const otherUserId = otherUserResult.rows[0].id;
        const messages = await pool.query(
            `SELECT m.id, m.sender_id, u.username as sender_username, m.message_text, m.created_at
             FROM private_messages m JOIN users u ON m.sender_id = u.id
             WHERE (sender_id = $1 AND recipient_id = $2) OR (sender_id = $2 AND recipient_id = $1) ORDER BY m.created_at ASC`, [userId, otherUserId]
        );
        res.json(messages.rows);
    } catch (err) { res.status(500).json({ message: 'Błąd.' }); }
});

function broadcast(message, excludePlayerId = null) {
  const messageStr = JSON.stringify(message);
  players.forEach((playerData, playerId) => {
    if (playerId !== excludePlayerId && playerData.ws.readyState === playerData.ws.OPEN) {
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
}

function notifyFriendsStatus(userId, isOnline) {
    (async () => {
        try {
            const friends = await pool.query(
                `SELECT user_id1, user_id2 FROM friendships WHERE (user_id1 = $1 OR user_id2 = $1) AND status = 'accepted'`, [userId]
            );
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
        const playerId = decoded.userId;
        const username = decoded.username;
        
        // --- POPRAWKA SPAWNU (LOSOWA POZYCJA) ---
        const startX = (Math.random() * 4) - 2;
        const startZ = (Math.random() * 4) - 2;
        
        players.set(playerId, { 
            ws, 
            nickname: username, 
            skinData: null, 
            thumbnail: null, 
            position: { x: startX, y: 0.9, z: startZ }, 
            quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 } 
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
                    broadcast({ type: 'playerJoined', id: playerId, nickname: currentPlayer.nickname, skinData: data.skinData, position: currentPlayer.position, quaternion: currentPlayer.quaternion }, playerId);
                }
                if (data.type === 'chatMessage') broadcast({ type: 'chatMessage', id: playerId, nickname: currentPlayer.nickname, text: data.text });
                
                if (data.type === 'playerMove') {
                    currentPlayer.position = data.position;
                    currentPlayer.quaternion = data.quaternion;
                    data.id = playerId;
                    broadcast(data, playerId);
                }

                if (data.type === 'collectCoin') {
                    if (currentCoin) {
                        currentCoin = null;
                        broadcast({ type: 'coinCollected' });
                        try { await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + $1 WHERE id = $2 RETURNING coins', [200, playerId]); } catch(e) {}
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