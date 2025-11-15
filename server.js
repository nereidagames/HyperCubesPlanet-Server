const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const https = require('https');

const port = process.env.PORT || 10000;
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Struktura gracza: { ws, nickname, skinData, position, quaternion }
const players = new Map();

// Endpoint używany przez "keep-alive service", aby zapobiec uśpieniu darmowej instancji na Render
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

// Funkcja do wysyłania wiadomości do wszystkich graczy, z opcją wykluczenia jednego z nich
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
  
  // Zapisujemy nowego gracza z jego domyślną pozycją startową
  players.set(playerId, { 
    ws: ws, 
    nickname: null,
    skinData: null,
    // POPRAWKA KRYTYCZNA: Pozycja startowa Y została zmieniona z 0.9 na 0.1.
    // Teraz idealnie pasuje do wysokości podłogi na kliencie (FLOOR_TOP_Y = 0.1),
    // ponieważ punkt odniesienia modelu postaci (origin) jest teraz na jego stopach.
    position: { x: 0, y: 0.1, z: 0 },
    quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 }
  });

  // Wysyłamy nowemu graczowi jego unikalne ID
  ws.send(JSON.stringify({ type: 'welcome', id: playerId }));
  
  // Przygotowujemy listę już istniejących graczy do wysłania nowemu graczowi
  const existingPlayers = [];
  players.forEach((pd, id) => {
    // Upewniamy się, że nie wysyłamy gracza do samego siebie i że gracz jest już "gotowy" (ma nick)
    if (id !== playerId && pd.nickname) { 
      existingPlayers.push({ id, nickname: pd.nickname, skinData: pd.skinData, position: pd.position, quaternion: pd.quaternion });
    }
  });
  // Jeśli są jacyś gracze, wysyłamy ich listę
  if (existingPlayers.length > 0) {
      ws.send(JSON.stringify({ type: 'playerList', players: existingPlayers }));
  }

  // Obsługa wiadomości od klienta
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      const currentPlayer = players.get(playerId);
      if (!currentPlayer) return;

      // Gracz wysyła tę wiadomość po wpisaniu nicku
      if (data.type === 'playerReady') {
        currentPlayer.nickname = data.nickname;
        currentPlayer.skinData = data.skinData;
        console.log(`Gracz ${playerId} jest gotowy z nickiem: ${data.nickname}`);
        
        // Informujemy wszystkich INNYCH graczy, że dołączył nowy gracz
        broadcast({ 
            type: 'playerJoined', 
            id: playerId, 
            nickname: data.nickname,
            skinData: data.skinData,
            position: currentPlayer.position,
            quaternion: currentPlayer.quaternion
        }, playerId);
        return;
      }

      // Gracz wysłał wiadomość na czacie
      if (data.type === 'chatMessage') {
        if (currentPlayer.nickname) {
          // Rozsyłamy wiadomość do WSZYSTKICH (włącznie z nadawcą, aby miał potwierdzenie)
          broadcast({
            type: 'chatMessage', id: playerId, nickname: currentPlayer.nickname, text: data.text
          });
        }
        return;
      }
      
      // Gracz zaktualizował swoją pozycję
      if (data.type === 'playerMove') {
        if (currentPlayer.nickname) {
          currentPlayer.position = data.position;
          currentPlayer.quaternion = data.quaternion;
          data.id = playerId; // Upewniamy się, że wiadomość zawiera ID gracza
          // Wysyłamy aktualizację pozycji do wszystkich INNYCH graczy
          broadcast(data, playerId);
        }
        return;
      }

    } catch (error) {
      console.error('Błąd podczas parsowania wiadomości:', error);
    }
  });

  // Obsługa zamknięcia połączenia
  ws.on('close', () => {
    console.log(`Gracz opuścił grę z ID: ${playerId}`);
    players.delete(playerId);
    // Informujemy wszystkich, że ten gracz wyszedł
    broadcast({ type: 'playerLeft', id: playerId });
  });

  // Obsługa błędów
  ws.on('error', (error) => {
    console.error(`Błąd WebSocket dla gracza ${playerId}:`, error);
  });
});

server.listen(port, () => {
  console.log(`Serwer nasłuchuje na porcie ${port}`);
  
  // Utrzymywanie aktywności serwera na platformie Render
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (RENDER_URL) {
    // Pingujemy serwer co 14 minut, aby zapobiec jego uśpieniu
    setInterval(() => {
      console.log('Wysyłanie pingu, aby utrzymać serwer aktywnym...');
      https.get(`${RENDER_URL}/ping`).on('error', (err) => {
        console.error('Błąd pingu:', err.message);
      });
    }, 840000); 
  }
});
