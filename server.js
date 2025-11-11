const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const https = require('https');

const port = process.env.PORT || 8080;
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// POPRAWKA: Teraz mapa przechowuje obiekty z danymi gracza, a nie tylko połączenie
const players = new Map(); // Struktura: { ws, nickname }

app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

// POPRAWKA: Zaktualizowana funkcja broadcast, aby działała z nową strukturą `players`
function broadcast(message, excludePlayerId = null) {
  players.forEach((playerData, playerId) => {
    if (playerId !== excludePlayerId && playerData.ws.readyState === playerData.ws.OPEN) {
      playerData.ws.send(JSON.stringify(message));
    }
  });
}

wss.on('connection', (ws) => {
  const playerId = crypto.randomUUID();
  console.log(`Gracz dołączył z ID: ${playerId}`);
  
  // Zapisujemy gracza z pustym nickiem na start
  players.set(playerId, { ws: ws, nickname: null });

  // 1. Witamy nowego gracza i wysyłamy mu jego ID
  ws.send(JSON.stringify({ type: 'welcome', id: playerId }));
  
  // 2. Wysyłamy nowemu graczowi listę wszystkich, którzy już są w grze (z ich nickami)
  const existingPlayers = [];
  players.forEach((playerData, id) => {
    if (id !== playerId && playerData.nickname) { // Wysyłaj tylko tych, którzy już ustawili nick
      existingPlayers.push({ id: id, nickname: playerData.nickname });
    }
  });
  if (existingPlayers.length > 0) {
      ws.send(JSON.stringify({ type: 'playerList', players: existingPlayers }));
  }

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      // POPRAWKA: Nowa logika do ustawiania nicku
      if (data.type === 'setNickname') {
        const playerData = players.get(playerId);
        if (playerData) {
          playerData.nickname = data.nickname;
          console.log(`Gracz ${playerId} ustawił nick na: ${data.nickname}`);
          // Informujemy wszystkich pozostałych, że nowy gracz w pełni dołączył (teraz mamy jego nick)
          broadcast({ type: 'playerJoined', id: playerId, nickname: data.nickname }, playerId);
        }
        return; // Kończymy obsługę tej wiadomości
      }

      // POPRAWKA: Dołączanie nicku do wiadomości czatu
      if (data.type === 'chatMessage') {
        const playerData = players.get(playerId);
        if (playerData && playerData.nickname) {
          const chatMessage = {
            type: 'chatMessage',
            id: playerId,
            nickname: playerData.nickname,
            text: data.text
          };
          // Rozgłoś wiadomość czatu do wszystkich (łącznie z nadawcą)
          broadcast(chatMessage);
        }
        return;
      }

      // Rozgłaszanie innych wiadomości (np. o ruchu)
      data.id = playerId;
      broadcast(data, playerId); // Wysyłaj do wszystkich oprócz nadawcy

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
        if (res.statusCode === 200) {
          console.log('Ping successful!');
        } else {
          console.error(`Ping failed with status code: ${res.statusCode}`);
        }
      }).on('error', (err) => {
        console.error('Error during self-ping:', err.message);
      });
    }, 840000); // 14 minut
  }
});
