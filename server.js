// Import potrzebnych bibliotek
const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto'); // Wbudowany moduł Node.js do generowania unikalnych ID
const https = require('https');   // Moduł do wysyłania zapytań HTTPS (dla "keep-alive")

// Ustawienie portu. Render automatycznie dostarczy zmienną środowiskową PORT.
// Lokalnie użyjemy 8080 jako domyślnego.
const port = process.env.PORT || 8080;

// Tworzenie aplikacji Express i serwera HTTP, który będzie jej używał
const app = express();
const server = http.createServer(app);

// Tworzenie serwera WebSocket i podłączanie go do naszego serwera HTTP
const wss = new WebSocketServer({ server });

// Mapa przechowująca dane wszystkich połączonych graczy.
// Kluczem będzie unikalne ID gracza, a wartością obiekt połączenia WebSocket.
const players = new Map();

// --- Endpoint /ping do utrzymywania serwera przy życiu na Render.com ---
// Gdy serwer otrzyma zapytanie HTTP na ten adres, po prostu odpowie "pong".
// To wystarczy, aby Render uznał go za "aktywny".
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

// Funkcja pomocnicza do rozgłaszania wiadomości do WSZYSTKICH połączonych graczy
function broadcast(message) {
  const serializedMessage = JSON.stringify(message);
  wss.clients.forEach(client => {
    // Sprawdzamy, czy połączenie z danym klientem jest wciąż otwarte
    if (client.readyState === client.OPEN) {
      client.send(serializedMessage);
    }
  });
}

// Główna logika serwera - co robić, gdy nowy gracz się połączy
wss.on('connection', (ws) => {
  // 1. Stwórz unikalne ID dla nowego gracza
  const playerId = crypto.randomUUID();
  console.log(`Gracz dołączył z ID: ${playerId}`);
  
  // 2. Zapisz połączenie gracza na naszej liście (mapie)
  players.set(playerId, ws);

  // 3. Wyślij wiadomość powitalną tylko do tego nowego gracza, informując go o jego ID
  ws.send(JSON.stringify({ type: 'welcome', id: playerId }));
  
  // 4. Wyślij nowemu graczowi listę wszystkich, którzy już są w grze
  const existingPlayers = Array.from(players.keys()).filter(id => id !== playerId);
  if (existingPlayers.length > 0) {
      ws.send(JSON.stringify({ type: 'playerList', players: existingPlayers }));
  }

  // 5. Poinformuj wszystkich POZOSTAŁYCH graczy, że ktoś nowy dołączył
  wss.clients.forEach(client => {
    if (client !== ws && client.readyState === client.OPEN) {
        client.send(JSON.stringify({ type: 'playerJoined', id: playerId }));
    }
  });

  // Logika wykonywana, gdy serwer otrzyma wiadomość od gracza
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      // Dołączamy ID nadawcy do wiadomości, aby inni gracze wiedzieli, od kogo ona pochodzi
      data.id = playerId;
      
      // Optymalizacja: Wiadomości o ruchu rozsyłamy do wszystkich OPRÓCZ nadawcy
      if (data.type === 'playerMove') {
          const serializedData = JSON.stringify(data);
          wss.clients.forEach(client => {
              if (client !== ws && client.readyState === client.OPEN) {
                  client.send(serializedData);
              }
          });
      } else {
        // Wszystkie inne typy wiadomości (np. czat) rozgłaszamy do wszystkich
        broadcast(data);
      }

    } catch (error) {
      console.error('Błąd podczas parsowania wiadomości:', error);
    }
  });

  // Logika wykonywana, gdy gracz się rozłączy (zamknie kartę, straci internet)
  ws.on('close', () => {
    console.log(`Gracz opuścił grę z ID: ${playerId}`);
    // Usuń gracza z listy
    players.delete(playerId);
    // Poinformuj wszystkich pozostałych, że ten gracz wyszedł
    broadcast({ type: 'playerLeft', id: playerId });
  });

  // Obsługa błędów dla pojedynczego połączenia
  ws.on('error', (error) => {
    console.error(`Błąd WebSocket dla gracza ${playerId}:`, error);
  });
});

// Uruchomienie serwera, aby nasłuchiwał na przychodzące połączenia
server.listen(port, () => {
  console.log(`Serwer nasłuchuje na porcie ${port}`);
  
  // --- Uruchomienie mechanizmu "keep-alive" po starcie serwera ---
  // Sprawdzamy, czy serwer działa na platformie Render (która udostępnia tę zmienną)
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (RENDER_URL) {
    // Ustawiamy interwał na 14 minut (840 000 ms), aby wysyłać zapytanie tuż przed uśpieniem
    setInterval(() => {
      console.log('Pinging self to prevent sleep...');
      // Wyślij zapytanie GET do naszego własnego endpointu /ping
      https.get(`${RENDER_URL}/ping`, (res) => {
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
