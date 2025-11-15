// Plik serwera (server.js)
// ...

wss.on('connection', (ws) => {
  const playerId = crypto.randomUUID();
  console.log(`Gracz połączył się z ID: ${playerId}`);
  
  players.set(playerId, { 
    ws: ws, 
    nickname: null,
    skinData: null,
    // POPRAWKA: Pozycja startowa Y jest teraz ustawiona na 0.1,
    // co odpowiada wysokości podłogi (FLOOR_TOP_Y) na kliencie.
    position: { x: 0, y: 0.1, z: 0 },
    quaternion: { _x: 0, _y: 0, _z: 0, _w: 1 }
  });

  // ... reszta kodu serwera bez zmian
});
