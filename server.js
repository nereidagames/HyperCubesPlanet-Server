require('dotenv').config();

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const https = require('https');

const port = process.env.PORT || 10000;
const app = express();

app.use(cors({ origin: '*' })); 
app.use(express.json({ limit: '50mb' })); 

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const players = new Map();
let currentCoin = null;
const MAP_BOUNDS = 30;

const XP_TABLE = [50, 75, 125, 150, 350, 750, 1500, 2000, 3000, 4000];

function getXpForNextLevel(currentLevel) {
    if (currentLevel <= XP_TABLE.length) {
        return XP_TABLE[currentLevel - 1];
    }
    return 4000 + ((currentLevel - 10) * 1000);
}

let nexusBlocksCache = [];

async function loadNexusMapToMemory() {
    try {
        const tableCheck = await pool.query(`SELECT to_regclass('public.nexus_map');`);
        if (!tableCheck.rows[0].to_regclass) return;

        const result = await pool.query('SELECT map_data FROM nexus_map WHERE id = 1');
        if (result.rows.length > 0) {
            nexusBlocksCache = result.rows[0].map_data || [];
            console.log(`[Server] Załadowano mapę Nexusa: ${nexusBlocksCache.length} bloków.`);
        } else {
            nexusBlocksCache = [];
        }
    } catch (e) {
        console.error("[Server] Błąd cache mapy:", e.message);
        nexusBlocksCache = [];
    }
}

async function autoMigrate() {
    console.log("[Server] Sprawdzanie struktury bazy danych...");
    try {
        // Users
        await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 0 NOT NULL;`); } catch(e){}
        try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS current_skin_thumbnail TEXT;`); } catch(e){}
        try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS owned_blocks JSONB DEFAULT '["Ziemia"]'::jsonb;`); } catch(e){}
        try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS level INTEGER DEFAULT 1;`); } catch(e){}
        try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS xp INTEGER DEFAULT 0;`); } catch(e){}
        try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS pending_xp INTEGER DEFAULT 0;`); } catch(e){}

        // Nexus
        await pool.query(`CREATE TABLE IF NOT EXISTS nexus_map (id INTEGER PRIMARY KEY CHECK (id = 1), map_data JSONB);`);
        const mapCheck = await pool.query(`SELECT id FROM nexus_map WHERE id = 1`);
        if (mapCheck.rowCount === 0) { await pool.query(`INSERT INTO nexus_map (id, map_data) VALUES (1, '[]'::jsonb)`); }

        // Skins
        await pool.query(`CREATE TABLE IF NOT EXISTS skins (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS skin_likes (id SERIAL PRIMARY KEY, skin_id INTEGER REFERENCES skins(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(skin_id, user_id));`);
        await pool.query(`CREATE TABLE IF NOT EXISTS skin_comments (id SERIAL PRIMARY KEY, skin_id INTEGER REFERENCES skins(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, text TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS skin_comment_likes (id SERIAL PRIMARY KEY, comment_id INTEGER REFERENCES skin_comments(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, UNIQUE(comment_id, user_id));`);

        // Prefabs
        await pool.query(`CREATE TABLE IF NOT EXISTS prefabs (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS prefab_likes (id SERIAL PRIMARY KEY, prefab_id INTEGER REFERENCES prefabs(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(prefab_id, user_id));`);
        await pool.query(`CREATE TABLE IF NOT EXISTS prefab_comments (id SERIAL PRIMARY KEY, prefab_id INTEGER REFERENCES prefabs(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, text TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS prefab_comment_likes (id SERIAL PRIMARY KEY, comment_id INTEGER REFERENCES prefab_comments(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, UNIQUE(comment_id, user_id));`);

        // Parts
        await pool.query(`CREATE TABLE IF NOT EXISTS hypercube_parts (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, blocks_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS part_likes (id SERIAL PRIMARY KEY, part_id INTEGER REFERENCES hypercube_parts(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(part_id, user_id));`);
        await pool.query(`CREATE TABLE IF NOT EXISTS part_comments (id SERIAL PRIMARY KEY, part_id INTEGER REFERENCES hypercube_parts(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, text TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS part_comment_likes (id SERIAL PRIMARY KEY, comment_id INTEGER REFERENCES part_comments(id) NOT NULL, user_id INTEGER REFERENCES users(id) NOT NULL, UNIQUE(comment_id, user_id));`);

        // Social & News
        await pool.query(`CREATE TABLE IF NOT EXISTS friendships (id SERIAL PRIMARY KEY, user_id1 INTEGER REFERENCES users(id) NOT NULL, user_id2 INTEGER REFERENCES users(id) NOT NULL, status VARCHAR(20) DEFAULT 'pending', created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id1, user_id2));`);
        await pool.query(`CREATE TABLE IF NOT EXISTS worlds (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) NOT NULL, name VARCHAR(100) NOT NULL, thumbnail TEXT, world_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS private_messages (id SERIAL PRIMARY KEY, sender_id INTEGER REFERENCES users(id) NOT NULL, recipient_id INTEGER REFERENCES users(id) NOT NULL, message_text TEXT NOT NULL, is_read BOOLEAN DEFAULT false, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);
        
        // FIX: Upewnienie się, że tabela user_news istnieje
        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_news (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                type VARCHAR(50) NOT NULL,
                source_user_id INTEGER REFERENCES users(id),
                target_id INTEGER,
                target_name VARCHAR(100),
                target_thumbnail TEXT,
                reward_xp INTEGER DEFAULT 0,
                reward_coins INTEGER DEFAULT 0,
                is_claimed BOOLEAN DEFAULT false,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await loadNexusMapToMemory();
        console.log("[Server] Baza danych gotowa.");
    } catch (e) {
        console.error("[Server] Błąd migracji:", e.message);
    }
}

app.get('/api/init-database', async (req, res) => {
    await autoMigrate();
    res.send("Migracja uruchomiona ręcznie.");
});

function parseOwnedBlocks(dbValue) {
    if (!dbValue) return ["Ziemia"];
    if (Array.isArray(dbValue)) return dbValue;
    if (typeof dbValue === 'string') {
        try { return JSON.parse(dbValue); } catch (e) { return ["Ziemia"]; }
    }
    return ["Ziemia"];
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- REWARDS LOGIC ---
async function addNews(userId, type, sourceUserId, targetId, targetName, targetThumbnail, xp, coins) {
    try {
        await pool.query(`
            INSERT INTO user_news (user_id, type, source_user_id, target_id, target_name, target_thumbnail, reward_xp, reward_coins)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [userId, type, sourceUserId, targetId, targetName, targetThumbnail, xp, coins]);
    } catch (e) {
        console.error("Błąd dodawania newsa:", e);
    }
}

async function handleLike(req, res, tableName, colName, parentTableName) {
    const objId = req.params.id;
    const userId = req.user.userId;
    try {
        const check = await pool.query(`SELECT id FROM ${tableName} WHERE ${colName} = $1 AND user_id = $2`, [objId, userId]);
        if (check.rows.length > 0) {
            // Unlike - remove like but keep news history (usually games don't remove reward notifications)
            await pool.query(`DELETE FROM ${tableName} WHERE ${colName} = $1 AND user_id = $2`, [objId, userId]);
        } else {
            // Like
            await pool.query(`INSERT INTO ${tableName} (${colName}, user_id) VALUES ($1, $2)`, [objId, userId]);
            
            // Nagroda dla właściciela
            const ownerRes = await pool.query(`SELECT owner_id, name, thumbnail FROM ${parentTableName} WHERE id = $1`, [objId]);
            if (ownerRes.rows.length > 0) {
                const { owner_id, name, thumbnail } = ownerRes.rows[0];
                if (owner_id !== userId) {
                    await addNews(owner_id, 'like_' + parentTableName, userId, objId, name, thumbnail, 100, 0);
                }
            }
        }
        const count = await pool.query(`SELECT COUNT(*) FROM ${tableName} WHERE ${colName} = $1`, [objId]);
        res.json({ success: true, likes: count.rows[0].count });
    } catch (e) { 
        console.error(e);
        res.status(500).json({ message: "DB Error" }); 
    }
}

async function handleGetComments(req, res, tableName, likesTable, colName) {
    const objId = req.params.id;
    try {
        const query = `
            SELECT c.id, c.text, c.created_at, u.username, u.current_skin_thumbnail,
            (SELECT COUNT(*) FROM ${likesTable} l WHERE l.comment_id = c.id) as likes
            FROM ${tableName} c JOIN users u ON c.user_id = u.id
            WHERE c.${colName} = $1 ORDER BY c.created_at DESC
        `;
        const r = await pool.query(query, [objId]);
        res.json(r.rows);
    } catch (e) { res.status(500).json({ message: "DB Error" }); }
}

async function handlePostComment(req, res, tableName, colName) {
    const objId = req.params.id;
    const { text } = req.body;
    if(!text || text.trim() === "") return res.status(400).json({message: "Pusty"});
    try {
        await pool.query(`INSERT INTO ${tableName} (${colName}, user_id, text) VALUES ($1, $2, $3)`, [objId, req.user.userId, text]);
        res.json({success: true});
    } catch (e) { res.status(500).json({message: "DB Error"}); }
}

async function handleLikeComment(req, res, tableName, commentsTable) {
    const commentId = req.params.id;
    const userId = req.user.userId;
    try {
        const check = await pool.query(`SELECT id FROM ${tableName} WHERE comment_id=$1 AND user_id=$2`, [commentId, userId]);
        if(check.rows.length > 0) {
            await pool.query(`DELETE FROM ${tableName} WHERE comment_id=$1 AND user_id=$2`, [commentId, userId]);
        } else {
            await pool.query(`INSERT INTO ${tableName} (comment_id, user_id) VALUES ($1, $2)`, [commentId, userId]);
            
            // Nagroda dla autora komentarza
            const authorRes = await pool.query(`SELECT user_id, text FROM ${commentsTable} WHERE id = $1`, [commentId]);
            if(authorRes.rows.length > 0) {
                const { user_id, text } = authorRes.rows[0];
                if(user_id !== userId) {
                    await addNews(user_id, 'like_comment', userId, commentId, text.substring(0, 20) + '...', null, 50, 0);
                }
            }
        }
        const count = await pool.query(`SELECT COUNT(*) FROM ${tableName} WHERE comment_id=$1`, [commentId]);
        res.json({success: true, likes: count.rows[0].count});
    } catch (e) { res.status(500).json({message: "DB Error"}); }
}

// --- API: NEWS & REWARDS ---
app.get('/api/news', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query(`
            SELECT n.*, u.username as source_username, u.current_skin_thumbnail as source_user_skin
            FROM user_news n
            LEFT JOIN users u ON n.source_user_id = u.id
            WHERE n.user_id = $1 AND n.is_claimed = false
            ORDER BY n.created_at DESC
        `, [req.user.userId]);
        res.json(r.rows);
    } catch(e) { 
        console.error(e);
        res.status(500).json({ message: "Błąd pobierania newsów" }); 
    }
});

app.post('/api/news/claim', authenticateToken, async (req, res) => {
    const { newsId } = req.body; 
    const userId = req.user.userId;
    
    try {
        let newsItems = [];
        if (newsId) {
            const r = await pool.query(`SELECT * FROM user_news WHERE id = $1 AND user_id = $2 AND is_claimed = false`, [newsId, userId]);
            newsItems = r.rows;
        } else {
            const r = await pool.query(`SELECT * FROM user_news WHERE user_id = $1 AND is_claimed = false`, [userId]);
            newsItems = r.rows;
        }

        if (newsItems.length === 0) return res.json({ success: false, message: "Brak nagród." });

        let totalXp = 0;
        let totalCoins = 0;

        const ids = newsItems.map(n => n.id);
        await pool.query(`UPDATE user_news SET is_claimed = true WHERE id = ANY($1)`, [ids]);

        newsItems.forEach(n => {
            totalXp += (n.reward_xp || 0);
            totalCoins += (n.reward_coins || 0);
        });

        const userRes = await pool.query('SELECT coins, level, xp FROM users WHERE id = $1', [userId]);
        let { coins, level, xp } = userRes.rows[0];
        
        coins = (coins || 0) + totalCoins;
        xp = (xp || 0) + totalXp;

        let levelUpOccurred = false;
        while (true) {
            const needed = getXpForNextLevel(level);
            if (xp >= needed) { xp -= needed; level++; levelUpOccurred = true; } else { break; }
        }

        await pool.query('UPDATE users SET coins = $1, level = $2, xp = $3 WHERE id = $4', [coins, level, xp, userId]);
        const nextLevelXp = getXpForNextLevel(level);

        res.json({
            success: true,
            totalXp,
            totalCoins,
            newCoins: coins,
            newLevel: level,
            newXp: xp,
            maxXp: nextLevelXp,
            levelUp: levelUpOccurred
        });

    } catch(e) { 
        console.error(e);
        res.status(500).json({ message: "Błąd serwera." }); 
    }
});

// --- API: USER ---
app.get('/api/user/me', authenticateToken, async (req, res) => { 
    try { 
        const r = await pool.query('SELECT id, username, coins, current_skin_thumbnail, owned_blocks, level, xp FROM users WHERE id = $1', [req.user.userId]); 
        if (r.rows.length === 0) return res.status(404).send(); 
        const u = r.rows[0]; 
        const nextLevelXp = getXpForNextLevel(u.level || 1); 
        
        const newsCountRes = await pool.query('SELECT COUNT(*) FROM user_news WHERE user_id = $1 AND is_claimed = false', [u.id]);
        const newsCount = parseInt(newsCountRes.rows[0].count);

        res.json({ 
            user: { 
                id: u.id, username: u.username, coins: u.coins || 0, ownedBlocks: parseOwnedBlocks(u.owned_blocks), 
                level: u.level || 1, xp: u.xp || 0, maxXp: nextLevelXp,
                pendingXp: newsCount 
            }, 
            thumbnail: u.current_skin_thumbnail 
        }); 
    } catch (e) { res.status(500).json({ message: e.message }); } 
});

// --- REST OF ENDPOINTS ---
app.get('/api/nexus', async (req, res) => {
    if (nexusBlocksCache && nexusBlocksCache.length > 0) return res.json(nexusBlocksCache);
    try { const result = await pool.query('SELECT map_data FROM nexus_map WHERE id = 1'); if (result.rows.length > 0) { nexusBlocksCache = result.rows[0].map_data || []; return res.json(nexusBlocksCache); } res.json([]); } catch (e) { res.status(500).json({ message: e.message }); }
});
app.post('/api/nexus', authenticateToken, async (req, res) => { const { blocks } = req.body; try { await pool.query(`INSERT INTO nexus_map (id, map_data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET map_data = $1`, [JSON.stringify(blocks)]); nexusBlocksCache = blocks; res.json({ message: 'Zapisano!' }); } catch (e) { res.status(500).json({ message: e.message }); } });

app.get('/api/skins/all', authenticateToken, async (req, res) => { try { const query = `SELECT s.id, s.name, s.thumbnail, s.owner_id, s.created_at, u.username as creator, u.level as "creatorLevel", u.current_skin_thumbnail as "creatorThumbnail", (SELECT COUNT(*) FROM skin_likes sl WHERE sl.skin_id = s.id) as likes, (SELECT COUNT(*) FROM skin_comments sc WHERE sc.skin_id = s.id) as comments FROM skins s JOIN users u ON s.owner_id = u.id ORDER BY s.created_at DESC LIMIT 50`; const r = await pool.query(query); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/skins/mine', authenticateToken, async (req, res) => { try { const query = `SELECT s.id, s.name, s.thumbnail, s.owner_id, s.created_at, u.username as creator, u.level as "creatorLevel", u.current_skin_thumbnail as "creatorThumbnail", (SELECT COUNT(*) FROM skin_likes sl WHERE sl.skin_id = s.id) as likes, (SELECT COUNT(*) FROM skin_comments sc WHERE sc.skin_id = s.id) as comments FROM skins s JOIN users u ON s.owner_id = u.id WHERE s.owner_id = $1 ORDER BY s.created_at DESC`; const r = await pool.query(query, [req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/skins/:id', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT blocks_data FROM skins WHERE id = $1`, [req.params.id]); if (r.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' }); res.json(r.rows[0].blocks_data); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/skins', authenticateToken, async (req, res) => { try { const r = await pool.query(`INSERT INTO skins (owner_id, name, blocks_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, req.body.name, JSON.stringify(req.body.blocks), req.body.thumbnail]); res.status(201).json({ message: 'Zapisano.', skinId: r.rows[0].id }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/skins/:id/like', authenticateToken, async (req, res) => { handleLike(req, res, 'skin_likes', 'skin_id', 'skins'); });
app.get('/api/skins/:id/comments', authenticateToken, async (req, res) => { handleGetComments(req, res, 'skin_comments', 'skin_comment_likes', 'skin_id'); });
app.post('/api/skins/:id/comments', authenticateToken, async (req, res) => { handlePostComment(req, res, 'skin_comments', 'skin_id'); });
app.post('/api/skins/comments/:id/like', authenticateToken, async (req, res) => { handleLikeComment(req, res, 'skin_comment_likes', 'skin_comments'); });

app.get('/api/prefabs/all', authenticateToken, async (req, res) => { try { const query = `SELECT p.id, p.name, p.thumbnail, p.owner_id, p.created_at, u.username as creator, u.level as "creatorLevel", u.current_skin_thumbnail as "creatorThumbnail", (SELECT COUNT(*) FROM prefab_likes pl WHERE pl.prefab_id = p.id) as likes, (SELECT COUNT(*) FROM prefab_comments pc WHERE pc.prefab_id = p.id) as comments FROM prefabs p JOIN users u ON p.owner_id = u.id ORDER BY p.created_at DESC LIMIT 50`; const r = await pool.query(query); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/prefabs/mine', authenticateToken, async (req, res) => { try { const query = `SELECT p.id, p.name, p.thumbnail, p.owner_id, p.created_at, u.username as creator, u.level as "creatorLevel", u.current_skin_thumbnail as "creatorThumbnail", (SELECT COUNT(*) FROM prefab_likes pl WHERE pl.prefab_id = p.id) as likes, (SELECT COUNT(*) FROM prefab_comments pc WHERE pc.prefab_id = p.id) as comments FROM prefabs p JOIN users u ON p.owner_id = u.id WHERE p.owner_id = $1 ORDER BY p.created_at DESC`; const r = await pool.query(query, [req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/prefabs/:id', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT blocks_data FROM prefabs WHERE id = $1`, [req.params.id]); if (r.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' }); res.json(r.rows[0].blocks_data); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/prefabs', authenticateToken, async (req, res) => { try { const r = await pool.query(`INSERT INTO prefabs (owner_id, name, blocks_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, req.body.name, JSON.stringify(req.body.blocks), req.body.thumbnail]); res.status(201).json({ message: 'Zapisano.', id: r.rows[0].id }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/prefabs/:id/like', authenticateToken, async (req, res) => { handleLike(req, res, 'prefab_likes', 'prefab_id', 'prefabs'); });
app.get('/api/prefabs/:id/comments', authenticateToken, async (req, res) => { handleGetComments(req, res, 'prefab_comments', 'prefab_comment_likes', 'prefab_id'); });
app.post('/api/prefabs/:id/comments', authenticateToken, async (req, res) => { handlePostComment(req, res, 'prefab_comments', 'prefab_id'); });
app.post('/api/prefabs/comments/:id/like', authenticateToken, async (req, res) => { handleLikeComment(req, res, 'prefab_comment_likes', 'prefab_comments'); });

app.get('/api/parts/all', authenticateToken, async (req, res) => { try { const query = `SELECT p.id, p.name, p.thumbnail, p.owner_id, p.created_at, u.username as creator, u.level as "creatorLevel", u.current_skin_thumbnail as "creatorThumbnail", (SELECT COUNT(*) FROM part_likes pl WHERE pl.part_id = p.id) as likes, (SELECT COUNT(*) FROM part_comments pc WHERE pc.part_id = p.id) as comments FROM hypercube_parts p JOIN users u ON p.owner_id = u.id ORDER BY p.created_at DESC LIMIT 50`; const r = await pool.query(query); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/parts/mine', authenticateToken, async (req, res) => { try { const query = `SELECT p.id, p.name, p.thumbnail, p.owner_id, p.created_at, u.username as creator, u.level as "creatorLevel", u.current_skin_thumbnail as "creatorThumbnail", (SELECT COUNT(*) FROM part_likes pl WHERE pl.part_id = p.id) as likes, (SELECT COUNT(*) FROM part_comments pc WHERE pc.part_id = p.id) as comments FROM hypercube_parts p JOIN users u ON p.owner_id = u.id WHERE p.owner_id = $1 ORDER BY p.created_at DESC`; const r = await pool.query(query, [req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/parts/:id', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT blocks_data FROM hypercube_parts WHERE id = $1`, [req.params.id]); if (r.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' }); res.json(r.rows[0].blocks_data); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/parts', authenticateToken, async (req, res) => { try { const r = await pool.query(`INSERT INTO hypercube_parts (owner_id, name, blocks_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, req.body.name, JSON.stringify(req.body.blocks), req.body.thumbnail]); res.status(201).json({ message: 'Zapisano.', id: r.rows[0].id }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/parts/:id/like', authenticateToken, async (req, res) => { handleLike(req, res, 'part_likes', 'part_id', 'hypercube_parts'); });
app.get('/api/parts/:id/comments', authenticateToken, async (req, res) => { handleGetComments(req, res, 'part_comments', 'part_comment_likes', 'part_id'); });
app.post('/api/parts/:id/comments', authenticateToken, async (req, res) => { handlePostComment(req, res, 'part_comments', 'part_id'); });
app.post('/api/parts/comments/:id/like', authenticateToken, async (req, res) => { handleLikeComment(req, res, 'part_comment_likes', 'part_comments'); });

app.post('/api/register', async (req, res) => { const { username, password } = req.body; try { const hash = await bcrypt.hash(password, 10); await pool.query(`INSERT INTO users (username, password_hash, coins, owned_blocks, level, xp) VALUES ($1, $2, 0, '["Ziemia"]'::jsonb, 1, 0)`, [username, hash]); res.status(201).json({ message: 'Utworzono.' }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/login', async (req, res) => { const { username, password } = req.body; try { const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]); const u = r.rows[0]; if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ message: 'Błąd logowania.' }); const token = jwt.sign({ userId: u.id, username: u.username }, process.env.JWT_SECRET, { expiresIn: '7d' }); const nextLevelXp = getXpForNextLevel(u.level || 1); res.json({ token, user: { id: u.id, username: u.username, coins: u.coins || 0, ownedBlocks: parseOwnedBlocks(u.owned_blocks), level: u.level || 1, xp: u.xp || 0, maxXp: nextLevelXp }, thumbnail: u.current_skin_thumbnail }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/parkour/complete', authenticateToken, async (req, res) => { const userId = req.user.userId; const rewardCoins = 100; const rewardXp = 500; try { const r = await pool.query('SELECT coins, level, xp FROM users WHERE id = $1', [userId]); if (r.rows.length === 0) return res.status(404).json({ message: "Użytkownik nie istnieje." }); let { coins, level, xp } = r.rows[0]; coins = (coins || 0) + rewardCoins; xp = (xp || 0) + rewardXp; level = level || 1; let levelUpOccurred = false; while (true) { const needed = getXpForNextLevel(level); if (xp >= needed) { xp -= needed; level++; levelUpOccurred = true; } else { break; } } await pool.query('UPDATE users SET coins = $1, level = $2, xp = $3 WHERE id = $4', [coins, level, xp, userId]); const nextLevelXp = getXpForNextLevel(level); res.json({ success: true, levelUp: levelUpOccurred, newCoins: coins, newLevel: level, newXp: xp, maxXp: nextLevelXp, message: levelUpOccurred ? `Awans na poziom ${level}!` : `Zdobyto ${rewardXp} XP i ${rewardCoins} monet!` }); } catch (e) { res.status(500).json({ message: "Błąd serwera." }); } });
app.post('/api/shop/buy', authenticateToken, async (req, res) => { const { blockName, cost } = req.body; const userId = req.user.userId; try { const userResult = await pool.query('SELECT coins, owned_blocks FROM users WHERE id = $1', [userId]); if (userResult.rows.length === 0) return res.status(404).json({ message: "Użytkownik nie istnieje" }); const user = userResult.rows[0]; const currentCoins = user.coins || 0; let ownedBlocks = parseOwnedBlocks(user.owned_blocks); if (ownedBlocks.includes(blockName)) return res.status(400).json({ message: "Już posiadasz ten blok!" }); if (currentCoins < cost) return res.status(400).json({ message: "Za mało monet!" }); ownedBlocks.push(blockName); const newBalance = currentCoins - cost; await pool.query('UPDATE users SET coins = $1, owned_blocks = $2 WHERE id = $3', [newBalance, JSON.stringify(ownedBlocks), userId]); res.json({ success: true, newBalance: newBalance, ownedBlocks: ownedBlocks }); } catch (e) { res.status(500).json({ message: "Błąd transakcji." }); } });
app.post('/api/worlds', authenticateToken, async (req, res) => { const { name, world_data, thumbnail } = req.body; if (!name || !world_data) return res.status(400).json({ message: "Brak danych." }); try { const r = await pool.query(`INSERT INTO worlds (owner_id, name, world_data, thumbnail) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.userId, name, JSON.stringify(world_data), thumbnail]); res.status(201).json({ message: 'Zapisano.', worldId: r.rows[0].id }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/worlds/all', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT w.id, w.name, w.thumbnail, w.owner_id, u.username as creator, w.world_data->>'type' as type FROM worlds w JOIN users u ON w.owner_id = u.id ORDER BY w.created_at DESC LIMIT 50`); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/worlds/:id', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT world_data FROM worlds WHERE id = $1`, [req.params.id]); if (r.rows.length === 0) return res.status(404).json({ message: 'Nie znaleziono.' }); res.json(r.rows[0].world_data); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/friends', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT u.id, u.username, u.current_skin_thumbnail FROM friendships f JOIN users u ON u.id = (CASE WHEN f.user_id1 = $1 THEN f.user_id2 ELSE f.user_id1 END) WHERE (f.user_id1 = $1 OR f.user_id2 = $1) AND f.status = 'accepted'`, [req.user.userId]); const reqs = await pool.query(`SELECT f.id as request_id, u.id as user_id, u.username, u.current_skin_thumbnail FROM friendships f JOIN users u ON u.id = f.user_id1 WHERE f.user_id2 = $1 AND f.status = 'pending'`, [req.user.userId]); const friends = r.rows.map(f => ({ ...f, isOnline: players.has(f.id) })); res.json({ friends, requests: reqs.rows }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/friends/search', authenticateToken, async (req, res) => { try { const r = await pool.query(`SELECT id, username, current_skin_thumbnail FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 10`, [`%${req.body.query}%`, req.user.userId]); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/friends/request', authenticateToken, async (req, res) => { const { targetUserId } = req.body; if(req.user.userId === targetUserId) return res.status(400).json({message: "Błąd."}); try { const chk = await pool.query(`SELECT * FROM friendships WHERE (user_id1=$1 AND user_id2=$2) OR (user_id1=$2 AND user_id2=$1)`, [req.user.userId, targetUserId]); if(chk.rows.length>0) return res.status(400).json({ message: 'Już istnieje.' }); await pool.query(`INSERT INTO friendships (user_id1, user_id2, status) VALUES ($1, $2, 'pending')`, [req.user.userId, targetUserId]); res.json({ message: 'Wysłano.' }); const t = players.get(parseInt(targetUserId)); if(t && t.ws.readyState===1) t.ws.send(JSON.stringify({ type: 'friendRequestReceived', from: req.user.username })); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/friends/accept', authenticateToken, async (req, res) => { try { const r = await pool.query(`UPDATE friendships SET status = 'accepted' WHERE id = $1 AND user_id2 = $2 AND status = 'pending' RETURNING user_id1`, [req.body.requestId, req.user.userId]); if(r.rowCount===0) return res.status(400).json({ message: 'Błąd.' }); res.json({ message: 'Przyjęto.' }); const sid = r.rows[0].user_id1; const ss = players.get(sid); if(ss && ss.ws.readyState===1){ ss.ws.send(JSON.stringify({ type: 'friendRequestAccepted', by: req.user.username })); ss.ws.send(JSON.stringify({ type: 'friendStatusChange' })); } const ms = players.get(parseInt(req.user.userId)); if(ms) ms.ws.send(JSON.stringify({ type: 'friendStatusChange' })); } catch (e) { res.status(500).json({ message: e.message }); } });
app.post('/api/coins/update', authenticateToken, async (req, res) => { try { const r = await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + $1 WHERE id = $2 RETURNING coins', [req.body.amount, req.user.userId]); res.json({ newBalance: r.rows[0].coins }); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/messages', authenticateToken, async (req, res) => { try { const userId = req.user.userId; const query = `SELECT DISTINCT ON (other_user_id) CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END AS other_user_id, u.username AS other_username, m.message_text, m.created_at FROM private_messages m JOIN users u ON u.id = (CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END) WHERE m.sender_id = $1 OR m.recipient_id = $1 ORDER BY other_user_id, m.created_at DESC`; const r = await pool.query(query, [userId]); const sorted = r.rows.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)); res.json(sorted); } catch (e) { res.status(500).json({ message: e.message }); } });
app.get('/api/messages/:username', authenticateToken, async (req, res) => { try { const userId = req.user.userId; const targetUsername = req.params.username; const userRes = await pool.query('SELECT id FROM users WHERE username = $1', [targetUsername]); if (userRes.rows.length === 0) return res.status(404).json({ message: 'Użytkownik nie istnieje.' }); const targetId = userRes.rows[0].id; const query = `SELECT m.sender_id, u.username AS sender_username, m.message_text, m.created_at FROM private_messages m JOIN users u ON m.sender_id = u.id WHERE (m.sender_id = $1 AND m.recipient_id = $2) OR (m.sender_id = $2 AND m.recipient_id = $1) ORDER BY m.created_at ASC`; const r = await pool.query(query, [userId, targetId]); res.json(r.rows); } catch (e) { res.status(500).json({ message: e.message }); } });

// WS
function broadcastToWorld(worldId, data, excludeId = null) { 
    const worldStr = String(worldId);
    const msg = JSON.stringify(data); 
    players.forEach((p, id) => { 
        if (String(p.currentWorld) === worldStr && id !== excludeId && p.ws.readyState === 1) { 
            p.ws.send(msg); 
        } 
    }); 
}

function spawnCoin() { 
    if (currentCoin) return; 
    const x = Math.floor((Math.random() - 0.5) * 2 * MAP_BOUNDS) + 0.5; 
    const z = Math.floor((Math.random() - 0.5) * 2 * MAP_BOUNDS) + 0.5; 
    const pos = getSmartSpawnPosition(x, z, false); 
    currentCoin = { position: pos }; 
    broadcastToWorld('nexus', { type: 'coinSpawned', position: currentCoin.position }); 
}

function notifyFriendsStatus(userId, isOnline) { (async () => { try { const r = await pool.query(`SELECT user_id1, user_id2 FROM friendships WHERE (user_id1=$1 OR user_id2=$1) AND status='accepted'`, [userId]); r.rows.forEach(row => { const fid = row.user_id1 === userId ? row.user_id2 : row.user_id1; const s = players.get(fid); if(s && s.ws.readyState===1) s.ws.send(JSON.stringify({ type: 'friendStatusChange' })); }); } catch (e) {} })(); }

wss.on('connection', (ws, req) => {
    ws.isAlive = true; ws.on('pong', () => { ws.isAlive = true; });
    const url = new URL(req.url, `http://${req.headers.host}`); const token = url.searchParams.get('token'); if (!token) { ws.close(1008); return; }
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) { ws.close(1008); return; }
        const playerId = parseInt(decoded.userId); const username = decoded.username; console.log(`[WS] ${username} online.`);
        let pos = { x: 0, y: 30, z: 0 };
        players.set(playerId, { ws, id: playerId, nickname: username, skinData: null, thumbnail: null, position: pos, quaternion: { _x:0,_y:0,_z:0,_w:1 }, currentWorld: 'nexus' });
        notifyFriendsStatus(playerId, true);
        setTimeout(() => { if (ws.readyState === ws.OPEN) { const startX = Math.floor((Math.random() * 6) - 3) + 0.5; const startZ = Math.floor((Math.random() * 6) - 3) + 0.5; const realPos = getSmartSpawnPosition(startX, startZ, true); const p = players.get(playerId); if(p) p.position = realPos; ws.send(JSON.stringify({ type: 'welcome', id: playerId, username: username, position: realPos })); const nexusPlayers = []; players.forEach((p, id) => { if (id !== playerId && String(p.currentWorld) === 'nexus') { nexusPlayers.push({ id: p.id, nickname: p.nickname, skinData: p.skinData, position: p.position, quaternion: p.quaternion }); } }); ws.send(JSON.stringify({ type: 'playerList', players: nexusPlayers })); if (currentCoin) ws.send(JSON.stringify({ type: 'coinSpawned', position: currentCoin.position })); } }, 1500);
        ws.on('message', async (message) => { try { const data = JSON.parse(message); const p = players.get(playerId); if (!p) return; if (data.type === 'joinWorld') { const oldWorld = String(p.currentWorld); const newWorld = String(data.worldId || 'nexus'); if (oldWorld !== newWorld) { broadcastToWorld(oldWorld, { type: 'playerLeft', id: playerId }, playerId); p.currentWorld = newWorld; if (newWorld === 'nexus') { p.position = getSmartSpawnPosition(0.5, 0.5, true); } else { p.position = { x: 0, y: 5, z: 0 }; } const roomPlayers = []; players.forEach((other, oid) => { if (oid !== playerId && String(other.currentWorld) === newWorld) { roomPlayers.push({ id: other.id, nickname: other.nickname, skinData: other.skinData, position: other.position, quaternion: other.quaternion }); } }); ws.send(JSON.stringify({ type: 'playerList', players: roomPlayers })); broadcastToWorld(newWorld, { type: 'playerJoined', id: playerId, nickname: username, skinData: p.skinData, position: p.position, quaternion: p.quaternion }, playerId); if (newWorld === 'nexus' && currentCoin) { ws.send(JSON.stringify({ type: 'coinSpawned', position: currentCoin.position })); } } return; } if (data.type === 'playerReady') { p.skinData = data.skinData; broadcastToWorld(p.currentWorld, { type: 'playerJoined', id: playerId, nickname: username, skinData: data.skinData, position: p.position, quaternion: p.quaternion }, playerId); } if (data.type === 'chatMessage') { broadcastToWorld(p.currentWorld, { type: 'chatMessage', id: playerId, nickname: username, text: data.text }); } if (data.type === 'playerMove') { p.position = data.position; p.quaternion = data.quaternion; broadcastToWorld(p.currentWorld, { type: 'playerMove', id: playerId, position: data.position, quaternion: data.quaternion }, playerId); } if (data.type === 'collectCoin') { if (String(p.currentWorld) === 'nexus' && currentCoin) { currentCoin = null; broadcastToWorld('nexus', { type: 'coinCollected' }); try { const r = await pool.query('UPDATE users SET coins = COALESCE(coins, 0) + 200 WHERE id = $1 RETURNING coins', [playerId]); if(r.rows.length > 0) ws.send(JSON.stringify({ type: 'updateBalance', newBalance: r.rows[0].coins })); } catch(e) {} setTimeout(spawnCoin, 5000); } } if (data.type === 'sendPrivateMessage') { const { recipient: recipientName, text } = data; try { const r = await pool.query('SELECT id FROM users WHERE username = $1', [recipientName]); if(r.rows.length > 0) { const recipientId = r.rows[0].id; await pool.query('INSERT INTO private_messages (sender_id, recipient_id, message_text) VALUES ($1, $2, $3)', [playerId, recipientId, text]); ws.send(JSON.stringify({ type: 'privateMessageSent', recipient: recipientName, text })); const rp = players.get(recipientId); if(rp && rp.ws.readyState===1) rp.ws.send(JSON.stringify({ type: 'privateMessageReceived', sender: { id: playerId, nickname: username }, text })); } } catch(e) {} } } catch (e) {} });
        ws.on('close', () => { const p = players.get(playerId); const worldId = p ? String(p.currentWorld) : 'nexus'; players.delete(playerId); notifyFriendsStatus(playerId, false); broadcastToWorld(worldId, { type: 'playerLeft', id: playerId }); });
    });
});

server.listen(port, () => { console.log(`Serwer: ${port}`); autoMigrate(); loadNexusMapToMemory(); setTimeout(spawnCoin, 10000); const RENDER_URL = process.env.RENDER_EXTERNAL_URL; if (RENDER_URL) setInterval(() => { https.get(RENDER_URL).on('error', () => {}); }, 840000); });
