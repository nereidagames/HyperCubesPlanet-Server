const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const https = require('https');

const port = process.env.PORT || 8080;
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Struktura gracza: { ws, nickname, skinData, position, quaternion }
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
  
  players.set(playerId, { 
    ws: ws, 
    nickname: null,
    skinData: null, // Gracz zaczyna bez skina
    position: { x: 0, y: 0.9, z: 0 },
    quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 }
  });

  ws.send(JSON.stringify({ type: 'welcome', id: playerId }));
  
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

      // --- POPRAWKA: Zmieniamy 'setNickname' na 'playerReady', które przyjmuje też skin ---
      if (data.type === 'playerReady') {
        currentPlayer.nickname = data.nickname;
        currentPlayer.skinData = data.skinData; // Zapisujemy dane skina
        console.log(`Gracz ${playerId} jest gotowy z nickiem: ${data.nickname}`);
        
        broadcast({ 
            type: 'playerJoined', 
            id: playerId, 
            nickname: data.nickname,
            skinData: data.skinData, // Rozgłaszamy dane skina
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
