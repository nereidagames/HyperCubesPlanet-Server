// Import potrzebnych bibliotek
const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto'); // Wbudowany moduł do generowania unikalnych ID

// Ustawienie portu, na którym serwer będzie nasłuchiwał
const port = process.env.PORT || 8080;

// Tworzenie aplikacji Express i serwera HTTP
const app = express();
const server = http.createServer(app);

// Tworzenie serwera WebSocket i podłączanie go do serwera HTTP
const wss = new WebSocketServer({ server });

// Mapa przechowująca dane wszystkich połączonych graczy
// Kluczem będzie unikalne ID gracza, a wartością obiekt WebSocket
const players = new Map();

// Funkcja do rozgłaszania wiadomości do wszystkich połączonych graczy
function broadcast(message) {
  wss.clients.forEach(client => {
    // Sprawdzamy, czy połączenie jest wciąż otwarte
    if (client.readyState === client.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// Logika, która wykonuje się, gdy nowy gracz (klient) się połączy
wss.on('connection', (ws) => {
  // 1. Generujemy unikalne ID dla nowego gracza
  const playerId = crypto.randomUUID();
  console.log(`Gracz dołączył z ID: ${playerId}`);

  // 2. Zapisujemy gracza na liście
  players.set(playerId, ws);

  // 3. Informujemy nowego gracza o jego własnym ID
  ws.send(JSON.stringify({ type: 'welcome', id: playerId }));
  
  // 4. Informujemy WSZYSTKICH graczy (łącznie z nowym) o aktualnej liście graczy
  // (Na razie to pusta informacja, ale w przyszłości będzie tu wysyłana pozycja startowa)
  broadcast({ type: 'playerList', players: Array.from(players.keys()) });

  // Logika, która wykonuje się, gdy serwer otrzyma wiadomość od gracza
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      // Dodajemy ID gracza do każdej wiadomości, aby inni wiedzieli, od kogo pochodzi
      data.id = playerId;

      // Rozgłaszamy otrzymaną wiadomość do wszystkich
      // To prosty serwer typu "przekaźnik" - co dostanie, to rozsyła dalej
      broadcast(data);

    } catch (error) {
      console.error('Błąd podczas parsowania wiadomości:', error);
    }
  });

  // Logika, która wykonuje się, gdy gracz się rozłączy
  ws.on('close', () => {
    console.log(`Gracz opuścił grę z ID: ${playerId}`);
    
    // 1. Usuwamy gracza z naszej listy
    players.delete(playerId);

    // 2. Informujemy wszystkich pozostałych graczy, że ten gracz wyszedł
    broadcast({ type: 'playerLeft', id: playerId });
  });

  ws.on('error', (error) => {
    console.error(`Błąd WebSocket dla gracza ${playerId}:`, error);
  });
});

// Uruchomienie serwera
server.listen(port, () => {
  console.log(`Serwer nasłuchuje na porcie ${port}`);
});