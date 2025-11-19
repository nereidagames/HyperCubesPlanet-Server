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

app.get('/api/init-database', async (req, res) => {
  const providedKey = req.query.key;
  if (!process.env.INIT_DB_SECRET_KEY || providedKey !== process.env.INIT_DB_SECRET_KEY) {
    return res.status(403).send('Brak autoryzacji.');
  }

  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      coins INTEGER DEFAULT 0 NOT NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `;
  try {
    await pool.query('SELECT NOW()');
    console.log('Połączenie z bazą danych udane.');
    await pool.query(createTableQuery);
    res.status(200).send('Tabela "users" została pomyślnie sprawdzona/stworzona.');
  } catch (err) {
    console.error('Błąd podczas inicjalizacji bazy danych:', err);
    res.status(500).send('Wystąpił błąd serwera podczas tworzenia tabeli.');
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
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Ta nazwa użytkownika jest już zajęta.' });
    }
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
    currentCoin = {
        position: { x, y: 1, z }
    };
    
    console.log(`Serwer stworzył monetę w: x=${x.toFixed(1)}, z=${z.toFixed(1)}`);
    broadcast({ type: 'coinSpawned', position: currentCoin.position });
}

wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');

    if (!token) {
        ws.close(1008, 'Brak tokenu uwierzytelniającego.');
        return;
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            ws.close(1008, 'Nieprawidłowy token.');
            return;
        }

        const playerId = decoded.userId;
        const username = decoded.username;
        console.log(`Gracz '${username}' (ID: ${playerId}) połączył się.`);
        
        players.set(playerId, { ws, nickname: username, skinData: null, position: { x: 0, y: 0.9, z: 0 }, quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 } });

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

                if (data.type === 'playerReady') {
                    currentPlayer.skinData = data.skinData;
                    broadcast({ 
                        type: 'playerJoined', 
                        id: playerId, 
                        nickname: currentPlayer.nickname,
                        skinData: data.skinData,
                        position: currentPlayer.position,
                        quaternion: currentPlayer.quaternion
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
                        currentPlayer.position = data.position;
                        currentPlayer.quaternion = data.quaternion;
                        data.id = playerId;
                        broadcast(data, playerId);
                    }
                    return;
                }

                if (data.type === 'collectCoin') {
                    if (currentCoin) {
                        console.log(`Gracz ${username} zbiera monetę.`);
                        currentCoin = null;

                        broadcast({ type: 'coinCollected' });

                        const result = await pool.query(
                            'UPDATE users SET coins = coins + $1 WHERE id = $2 RETURNING coins',
                            [200, playerId]
                        );
                        
                        if (result.rows.length > 0) {
                            ws.send(JSON.stringify({ type: 'updateBalance', newBalance: result.rows[0].coins }));
                        }

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
  
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (RENDER_URL) {
    setInterval(() => {
      console.log('Pinging self to prevent sleep...');
      https.get(RENDER_URL, (res) => {
        if (res.statusCode === 200) {
          console.log('Ping successful!');
        } else {
          console.error(`Ping failed with status code: ${res.statusCode}`);
        }
      }).on('error', (err) => {
        console.error('Error during self-ping:', err.message);
      });
    }, 840000);
  }
});
