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
  console.log(`[SERVER BROADCAST] Rozgłaszam (do wszystkich oprócz ${excludePlayerId || 'nikogo'}): ${messageStr}`);
  players.forEach((playerData, playerId) => {
    if (playerId !== excludePlayerId && playerData.ws.readyState === playerData.ws.OPEN) {
      playerData.ws.send(messageStr);
    }
  });
}

wss.on('connection', (ws) => {
  const playerId = crypto.randomUUID();
  console.log(`[SERVER] Gracz dołączył z ID: ${playerId}`);
  
  players.set(playerId, { 
    ws: ws, 
    nickname: null,
    position: { x: 0, y: 0.9, z: 0 },
    quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 }
  });

  const welcomeMsg = JSON.stringify({ type: 'welcome', id: playerId });
  console.log(`[SERVER SEND] Wysyłam do ${playerId}: ${welcomeMsg}`);
  ws.send(welcomeMsg);
  
  const existingPlayers = [];
  players.forEach((playerData, id) => {
    if (id !== playerId && playerData.nickname) { 
      existingPlayers.push({ id, nickname: playerData.nickname, position: playerData.position, quaternion: playerData.quaternion });
    }
  });

  if (existingPlayers.length > 0) {
      const playerListMsg = JSON.stringify({ type: 'playerList', players: existingPlayers });
      console.log(`[SERVER SEND] Wysyłam listę graczy do ${playerId}: ${playerListMsg}`);
      ws.send(playerListMsg);
  }

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log(`[SERVER RECEIVE] Otrzymano od ${playerId}: ${JSON.stringify(data)}`);
      
      const currentPlayer = players.get(playerId);
      if (!currentPlayer) return;

      if (data.type === 'setNickname') {
        currentPlayer.nickname = data.nickname;
        console.log(`[SERVER INFO] Gracz ${playerId} ustawił nick na: ${data.nickname}`);
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
            type: 'chatMessage',
            id: playerId,
            nickname: currentPlayer.nickname,
            text: data.text
          });
        }
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
    console.log(`[SERVER] Gracz opuścił grę z ID: ${playerId}`);
    players.delete(playerId);
    broadcast({ type: 'playerLeft', id: playerId });
  });

  ws.on('error', (error) => {
    console.error(`[SERVER ERROR] Błąd WebSocket dla gracza ${playerId}:`, error);
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
