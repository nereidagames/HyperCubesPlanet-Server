const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const port = process.env.PORT || 10000;
const app = express();
app.use(express.json());
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const players = new Map();

// --- NOWOŚĆ: BEZPIECZNY ENDPOINT DO INICJALIZACJI BAZY DANYCH ---
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
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `;

  try {
    await pool.query(createTableQuery);
    res.status(200).send('Tabela "users" została pomyślnie sprawdzona/stworzona.');
  } catch (err) {
    console.error('Błąd podczas tworzenia tabeli:', err);
    res.status(500).send('Wystąpił błąd serwera podczas tworzenia tabeli.');
  }
});

// --- API HTTP DO REJESTRACJI I LOGOWANIA ---

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Nazwa użytkownika i hasło są wymagane.' });
  }

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

  if (!username || !password) {
    return res.status(400).json({ message: 'Nazwa użytkownika i hasło są wymagane.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ message: 'Użytkownik o takiej nazwie nie istnieje.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: 'Nieprawidłowe hasło.' });
    }

    const payload = { userId: user.id, username: user.username };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { id: user.id, username: user.username } });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Wystąpił błąd serwera.' });
  }
});

// --- SERWER WEBSOCKET DO GRY ---

function broadcast(message, excludePlayerId = null) {
  const messageStr = JSON.stringify(message);
  players.forEach((playerData, playerId) => {
    if (playerId !== excludePlayerId && playerData.ws.readyState === playerData.ws.OPEN) {
      playerData.ws.send(messageStr);
    }
  });
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
        
        players.set(playerId, { 
            ws: ws, 
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

        ws.on('message', (message) => {
            try {
                const data = JSON.parse(message);
                const currentPlayer = players.get(playerId);
                if (!currentPlayer) return;

                if (data.type === 'playerReady') {
                    currentPlayer.skinData = data.skinData;
                    console.log(`Gracz ${playerId} zaktualizował skin.`);
                    
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
});
