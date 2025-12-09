require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 10000;

app.use(cors({ origin: '*' }));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Prosty endpoint, żeby sprawdzić czy serwer żyje
app.get('/', (req, res) => {
    res.send('Serwer w trybie awaryjnym działa.');
});

// --- TWARDY RESET BAZY DANYCH ---
app.get('/api/hard-reset', async (req, res) => {
    try {
        console.log("ROZPOCZYNAM CZYSZCZENIE BAZY...");
        
        // 1. Usuwamy wszystko (kaskadowo)
        await pool.query(`
            DROP TABLE IF EXISTS skin_comment_likes CASCADE;
            DROP TABLE IF EXISTS skin_comments CASCADE;
            DROP TABLE IF EXISTS skin_likes CASCADE;
            DROP TABLE IF EXISTS prefab_comment_likes CASCADE;
            DROP TABLE IF EXISTS prefab_comments CASCADE;
            DROP TABLE IF EXISTS prefab_likes CASCADE;
            DROP TABLE IF EXISTS prefabs CASCADE;
            DROP TABLE IF EXISTS part_comment_likes CASCADE;
            DROP TABLE IF EXISTS part_comments CASCADE;
            DROP TABLE IF EXISTS part_likes CASCADE;
            DROP TABLE IF EXISTS hypercube_parts CASCADE;
            DROP TABLE IF EXISTS private_messages CASCADE;
            DROP TABLE IF EXISTS worlds CASCADE;
            DROP TABLE IF EXISTS friendships CASCADE;
            DROP TABLE IF EXISTS skins CASCADE;
            DROP TABLE IF EXISTS nexus_map CASCADE;
            DROP TABLE IF EXISTS users CASCADE;
        `);

        console.log("Tabele usunięte. Tworzenie nowych...");

        // 2. Tworzymy wszystko na czysto
        await pool.query(`
            CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, coins INTEGER DEFAULT 0, current_skin_thumbnail TEXT, owned_blocks JSONB DEFAULT '["Ziemia"]'::jsonb, level INTEGER DEFAULT 1, xp INTEGER DEFAULT 0, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE nexus_map (id INTEGER PRIMARY KEY CHECK (id = 1), map_data JSONB);
            CREATE TABLE skins (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE friendships (id SERIAL PRIMARY KEY, user_id1 INTEGER REFERENCES users(id) NOT NULL, user_id2 INTEGER REFERENCES users(id) NOT NULL, status VARCHAR(20) DEFAULT 'pending', created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id1, user_id2));
            CREATE TABLE worlds (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, world_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE private_messages (id SERIAL PRIMARY KEY, sender_id INTEGER REFERENCES users(id) NOT NULL, recipient_id INTEGER REFERENCES users(id) NOT NULL, message_text TEXT NOT NULL, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            
            CREATE TABLE skin_likes (id SERIAL PRIMARY KEY, skin_id INTEGER REFERENCES skins(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(skin_id, user_id));
            CREATE TABLE skin_comments (id SERIAL PRIMARY KEY, skin_id INTEGER REFERENCES skins(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, text TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE skin_comment_likes (id SERIAL PRIMARY KEY, comment_id INTEGER REFERENCES skin_comments(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, UNIQUE(comment_id, user_id));
            
            CREATE TABLE prefabs (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE prefab_likes (id SERIAL PRIMARY KEY, prefab_id INTEGER REFERENCES prefabs(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(prefab_id, user_id));
            CREATE TABLE prefab_comments (id SERIAL PRIMARY KEY, prefab_id INTEGER REFERENCES prefabs(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, text TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE prefab_comment_likes (id SERIAL PRIMARY KEY, comment_id INTEGER REFERENCES prefab_comments(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, UNIQUE(comment_id, user_id));

            CREATE TABLE hypercube_parts (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE part_likes (id SERIAL PRIMARY KEY, part_id INTEGER REFERENCES hypercube_parts(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(part_id, user_id));
            CREATE TABLE part_comments (id SERIAL PRIMARY KEY, part_id INTEGER REFERENCES hypercube_parts(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, text TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE part_comment_likes (id SERIAL PRIMARY KEY, comment_id INTEGER REFERENCES part_comments(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, UNIQUE(comment_id, user_id));

            INSERT INTO nexus_map (id, map_data) VALUES (1, '[]'::jsonb);
        `);

        res.send("<h1>SUKCES! Baza danych została zresetowana.</h1><p>Teraz wgraj z powrotem pełny plik server.js i spróbuj się zarejestrować w grze.</p>");
    } catch (e) {
        console.error(e);
        res.send(`<h1>BŁĄD:</h1><pre>${e.message}</pre>`);
    }
});

app.listen(port, () => console.log(`Serwer AWARYJNY nasłuchuje na porcie ${port}`));