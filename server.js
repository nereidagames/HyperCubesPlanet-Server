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
app.use(express.json());
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const players = new Map();
let currentCoin = null;
const MAP_BOUNDS = 30; // Granice spawnowania monet

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

// Endpoint do inicjalizacji bazy danych (zabezpieczony kluczem)
app.get('/api/init-database', async (req, res) => {
  const providedKey = req.query.key;
  if (!process.env.INIT_DB_SECRET_KEY || providedKey !== process.env.INIT_DB_SECRET_KEY) {
    return res.status(403).send('Brak autoryzacji.');
  }

  const createUsersTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      coins INTEGER DEFAULT 0 NOT NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `;
  const createMessagesTableQuery = `
    CREATE TABLE IF NOT EXISTS private_messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER REFERENCES users(id) NOT NULL,
      recipient_id INTEGER REFERENCES users(id) NOT NULL,
      message_text TEXT NOT NULL,
      is_read BOOLEAN DEFAULT false,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `;

  try {
    await pool.query(createUsersTableQuery);
    await pool.query(createMessagesTableQuery);
    res.status(200).send('Tabele "users" i "private_messages" zostały pomyślnie sprawdzone/stworzone.');
  } catch (err) {
    console.error('Błąd podczas inicjalizacji bazy danych:', err);
    res.status(500).send('Wystąpił błąd serwera podczas tworzenia tabel.');
  }
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Nazwa użytkownika i hasło są wymagane.' });

  try {
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);
    const newUser = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, password_hash]
    );
    res.status(201).json({ user: newUser.rows[0], message: 'Konto zostało pomyślnie utworzone.' });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ message: 'Ta nazwa użytkownika jest już zajęta.' });
    console.error(err);
    res.status(500).json({ message: 'Wystąpił błąd serwera.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Nazwa użytkownika i hasło są wymagane.' });

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: 'Użytkownik o takiej nazwie nie istnieje.' });
    
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ message: 'Nieprawidłowe hasło.' });

    const payload = { userId: user.id, username: user.username };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { id: user.id, username: user.username, coins: user.coins } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Wystąpił błąd serwera.' });
  }
});

app.post('/api/coins/update', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const userId = req.user.userId;

    if (typeof amount !== 'number') return res.status(400).json({ message: 'Nieprawidłowa kwota.' });

    try {
        if (amount < 0) {
            const currentBalanceResult = await pool.query('SELECT coins FROM users WHERE id = $1', [userId]);
            if (currentBalanceResult.rows[0].coins < Math.abs(amount)) {
                return res.status(403).json({ message: 'Niewystarczająca ilość monet.' });
            }
        }
        
        const result = await pool.query(
            'UPDATE users SET coins = coins + $1 WHERE id = $2 RETURNING coins',
            [amount, userId]
        );
        
        const newBalance = result.rows[0].coins;
        res.json({ newBalance });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Błąd serwera podczas aktualizacji monet.' });
    }
});

app.get('/api/messages', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const result = await pool.query(
            `SELECT DISTINCT ON (other_user_id) other_user_id, other_username, message_text, created_at
             FROM (
                SELECT
                    CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END as other_user_id,
                    m.message_text,
                    m.created_at
                FROM private_messages m
                WHERE m.sender_id = $1 OR m.recipient_id = $1
                ORDER BY m.created_at DESC
             ) AS sub
             JOIN users u ON u.id = sub.other_user_id
             GROUP BY other_user_id, other_username, message_text, created_at
             ORDER BY created_at DESC`, [userId]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Błąd serwera przy pobieraniu konwersacji.' });
    }
});

app.get('/api/messages/:username', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const otherUsername = req.params.username;
    try {
        const otherUserResult = await pool.query('SELECT id FROM users WHERE username = $1', [otherUsername]);
        if (otherUserResult.rows.length === 0) {
            return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });
        }
        const otherUserId = otherUserResult.rows[0].id;

        const messages = await pool.query(
            `SELECT m.id, m.sender_id, u.username as sender_username, m.message_text, m.created_at
             FROM private_messages m
             JOIN users u ON m.sender_id = u.id
             WHERE (sender_id = $1 AND recipient_id = $2) OR (sender_id = $2 AND recipient_id = $1)
             ORDER BY m.created_at ASC`,
            [userId, otherUserId]
        );
        res.json(messages.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Błąd serwera przy pobieraniu wiadomości.' });
    }
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
    console.log(`Zrespiono monetę na: ${x.toFixed(2)}, ${z.toFixed(2)}`);
}

wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');

    if (!token) { ws.close(1008, 'Brak tokenu.'); return; }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) { ws.close(1008, 'Nieprawidłowy token.'); return; }

        const playerId = decoded.userId;
        const username = decoded.username;
        console.log(`Gracz '${username}' (ID: ${playerId}) połączył się.`);
        
        // Przechowujemy stan gracza na serwerze
        players.set(playerId, { 
            ws, 
            nickname: username, 
            skinData: null, 
            position: { x: 0, y: 0.9, z: 0 }, 
            quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 } 
        });

        ws.send(JSON.stringify({ type: 'welcome', id: playerId, username: username }));

        const existingPlayers = [];
        players.forEach((pd, id) => {
            if (id !== playerId && pd.nickname) { 
                existingPlayers.push({ id, nickname: pd.nickname, skinData: pd.skinData, position: pd.position, quaternion: pd.quaternion });
            }
        });
        if (existingPlayers.length > 0) {
            ws.send(JSON.stringify({ type: 'playerList', players: existingPlayers }));
        }

        if (currentCoin) {
            ws.send(JSON.stringify({ type: 'coinSpawned', position: currentCoin.position }));
        }

        ws.on('message', async (message) => {
            try {
                const data = JSON.parse(message);
                const currentPlayer = players.get(playerId);
                if (!currentPlayer) return;

                if (data.type === 'sendPrivateMessage') {
                    const recipientUsername = data.recipient;
                    const messageText = data.text;

                    const recipientResult = await pool.query('SELECT id FROM users WHERE username = $1', [recipientUsername]);
                    if (recipientResult.rows.length === 0) {
                        ws.send(JSON.stringify({ type: 'privateMessageError', message: 'Nie znaleziono takiego gracza.' }));
                        return;
                    }
                    const recipientId = recipientResult.rows[0].id;
                    
                    await pool.query(
                        'INSERT INTO private_messages (sender_id, recipient_id, message_text) VALUES ($1, $2, $3)',
                        [playerId, recipientId, messageText]
                    );

                    const recipientData = players.get(recipientId);
                    if (recipientData && recipientData.ws.readyState === recipientData.ws.OPEN) {
                        recipientData.ws.send(JSON.stringify({
                            type: 'privateMessageReceived',
                            sender: { id: playerId, nickname: currentPlayer.nickname },
                            text: messageText
                        }));
                    }
                    return;
                }

                if (data.type === 'playerReady') {
                    currentPlayer.skinData = data.skinData;
                    broadcast({ 
                        type: 'playerJoined', id: playerId, nickname: currentPlayer.nickname, skinData: data.skinData,
                        position: currentPlayer.position, quaternion: currentPlayer.quaternion
                    }, playerId);
                    return;
                }

                if (data.type === 'chatMessage') {
                    if (currentPlayer.nickname) {
                        broadcast({
                            type: 'chatMessage', id: playerId, nickname: currentPlayer.nickname, text: data.text
                        });
                    }
                    return;
                }
                
                if (data.type === 'playerMove') {
                    if (currentPlayer.nickname) {
                        // Aktualizuj pozycję gracza na serwerze - KLUCZOWE DLA ANTI-CHEATA
                        currentPlayer.position = data.position;
                        currentPlayer.quaternion = data.quaternion;
                        
                        // Prześlij ruch do innych
                        data.id = playerId;
                        broadcast(data, playerId);
                    }
                    return;
                }

                // --- ANTI-CHEAT I ZBIERANIE MONET ---
                if (data.type === 'collectCoin') {
                    if (currentCoin) {
                        // 1. Oblicz dystans gracza do monety (Anti-Cheat)
                        const dx = currentPlayer.position.x - currentCoin.position.x;
                        const dy = currentPlayer.position.y - currentCoin.position.y; // Opcjonalnie, jeśli moneta jest wysoko
                        const dz = currentPlayer.position.z - currentCoin.position.z;
                        const distance = Math.sqrt(dx * dx + dy * dy + dz * dz);

                        // Tolerancja 5 jednostek (moneta ma hit box, plus lag sieciowy)
                        if (distance > 5.0) {
                            console.warn(`Podejrzana próba zebrania monety przez ${currentPlayer.nickname}. Dystans: ${distance}`);
                            return;
                        }

                        // 2. Usuń monetę natychmiast (zapobiega podwójnemu zebraniu)
                        currentCoin = null;
                        broadcast({ type: 'coinCollected' });

                        // 3. Dodaj monety w bazie
                        try {
                            const result = await pool.query(
                                'UPDATE users SET coins = coins + $1 WHERE id = $2 RETURNING coins',
                                [200, playerId]
                            );
                            if (result.rows.length > 0) {
                                ws.send(JSON.stringify({ type: 'updateBalance', newBalance: result.rows[0].coins }));
                            }
                        } catch (dbErr) {
                            console.error("Błąd bazy danych przy dodawaniu monet:", dbErr);
                        }

                        // 4. Zaplanuj spawn nowej monety
                        setTimeout(spawnCoin, 5000);
                    }
                    return;
                }

            } catch (error) {
                console.error('Błąd podczas parsowania wiadomości:', error);
            }
        });

        ws.on('close', () => {
            console.log(`Gracz opuścił grę z ID: ${playerId}`);
            players.delete(playerId);
            broadcast({ type: 'playerLeft', id: playerId });
        });

        ws.on('error', (error) => {
            console.error(`Błąd WebSocket dla gracza ${playerId}:`, error);
        });
    });
});

server.listen(port, () => {
  console.log(`Serwer nasłuchuje na porcie ${port}`);
  
  setTimeout(spawnCoin, 10000);
  
  // Pingowanie serwera Render, żeby nie zasnął
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (RENDER_URL) {
    setInterval(() => {
      https.get(RENDER_URL).on('error', (err) => {
        console.error('Błąd pingu:', err.message);
      });
    }, 840000);
  }
});