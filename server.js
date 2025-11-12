const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const https = require('https');

const port = process.env.PORT || 8080;
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Struktura gracza: { ws, nickname, position, quaternion }
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
  console.log(`Gracz połączył się z ID: ${playerId}`);
  
  // Zapisujemy gracza, ale jeszcze bez nicku (nie jest "gotowy")
  players.set(playerId, { 
    ws: ws, 
    nickname: null,
    position: { x: 0, y: 0.9, z: 0 },
    quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 }
  });

  // 1. Witamy nowego gracza
  ws.send(JSON.stringify({ type: 'welcome', id: playerId }));
  
  // 2. Wysyłamy nowemu graczowi listę tych, którzy już są w pełni w grze
  const existingPlayers = [];
  players.forEach((pd, id) => {
    if (id !== playerId && pd.nickname) { // Wysyłaj tylko "gotowych" graczy
      existingPlayers.push({ id, nickname: pd.nickname, position: pd.position, quaternion: pd.quaternion });
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

      if (data.type === 'setNickname') {
        currentPlayer.nickname = data.nickname;
        console.log(`Gracz ${playerId} jest gotowy z nickiem: ${data.nickname}`);
        // TERAZ jest gotowy. Informujemy wszystkich pozostałych.
        broadcast({ 
            type: 'playerJoined', 
            id: playerId, 
            nickname: data.nickname,
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
        if (currentPlayer.nickname) { // Wysyłaj pozycję tylko jeśli gracz jest w pełni dołączony
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

server.listen(port, () => {
  console.log(`Serwer nasłuchuje na porcie ${port}`);
  
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (RENDER_URL) {
    setInterval(() => {
      https.get(`${RENDER_URL}/ping`).on('error', (err) => {
        console.error('Błąd pingu:', err.message);
      });
    }, 840000);
  }
});
