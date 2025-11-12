const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const https = require('https');

const port = process.env.PORT || 8080;
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const players = new Map();

app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

function broadcast(message, excludePlayerId = null) {
  const messageStr = JSON.stringify(message);
  players.forEach((playerData, playerId) => {
    if (playerId !== excludePlayerId && playerData.ws.readyState === playerData.ws.OPEN) {
      playerData.ws.send(messageStr);
    }
  });
}

wss.on('connection', (ws) => {
  const playerId = crypto.randomUUID();
  console.log(`Gracz dołączył z ID: ${playerId}`);
  
  const playerData = { 
    ws: ws, 
    nickname: `Player_${playerId.substring(0, 4)}`, // Domyślny nick od razu
    position: { x: 0, y: 0.9, z: 0 },
    quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 }
  };
  players.set(playerId, playerData);

  // 1. Witamy nowego gracza
  ws.send(JSON.stringify({ type: 'welcome', id: playerId }));
  
  // 2. Wysyłamy nowemu graczowi listę wszystkich, którzy już są w grze
  const existingPlayers = [];
  players.forEach((pd, id) => {
    if (id !== playerId) { 
      existingPlayers.push({ id, nickname: pd.nickname, position: pd.position, quaternion: pd.quaternion });
    }
  });
  if (existingPlayers.length > 0) {
      ws.send(JSON.stringify({ type: 'playerList', players: existingPlayers }));
  }

  // 3. Natychmiast informujemy wszystkich pozostałych, że nowy gracz dołączył (z domyślnym nickiem)
  broadcast({ 
      type: 'playerJoined', 
      id: playerId, 
      nickname: playerData.nickname,
      position: playerData.position,
      quaternion: playerData.quaternion
  }, playerId);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      const currentPlayer = players.get(playerId);
      if (!currentPlayer) return;

      if (data.type === 'setNickname') {
        currentPlayer.nickname = data.nickname;
        console.log(`Gracz ${playerId} zaktualizował nick na: ${data.nickname}`);
        // Informujemy wszystkich o aktualizacji nicku
        broadcast({ type: 'updateNickname', id: playerId, nickname: data.nickname });
        return;
      }

      if (data.type === 'chatMessage') {
        broadcast({
          type: 'chatMessage',
          id: playerId,
          nickname: currentPlayer.nickname,
          text: data.text
        });
        return;
      }
      
      if (data.type === 'playerMove') {
        currentPlayer.position = data.position;
        currentPlayer.quaternion = data.quaternion;
        
        data.id = playerId;
        broadcast(data, playerId);
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

server.listen(port, () => {
  console.log(`Serwer nasłuchuje na porcie ${port}`);
  
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (RENDER_URL) {
    setInterval(() => {
      console.log('Pinging self to prevent sleep...');
      https.get(`${RENDER_URL}/ping`, (res) => {
        res.statusCode === 200 ? console.log('Ping successful!') : console.error(`Ping failed: ${res.statusCode}`);
      }).on('error', (err) => {
        console.error('Error during self-ping:', err.message);
      });
    }, 840000);
  }
});
