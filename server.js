require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 10000;

// CORS configuration - Allow your xmit.co domain
const corsOptions = {
    origin: [
        'https://scripthub.xmit.dev',
        'http://localhost:3000',
        'https://*.xmit.dev'
    ],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api/', limiter);

// Ensure database directory exists
const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

// Initialize database
const dbPath = path.join(dbDir, 'xmithub.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Initialize tables
const initDb = () => {
    const createTables = `
        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            image_url TEXT,
            actual_loadstring TEXT NOT NULL,
            display_likes INTEGER DEFAULT 0,
            display_downloads INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS redeemed_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workink_key TEXT UNIQUE NOT NULL,
            script_id INTEGER,
            key_token TEXT UNIQUE,
            is_used BOOLEAN DEFAULT 0,
            redeemed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY (script_id) REFERENCES scripts(id)
        );

        CREATE TABLE IF NOT EXISTS loadstrings (
            id TEXT PRIMARY KEY,
            script_id INTEGER NOT NULL,
            actual_loadstring TEXT NOT NULL,
            key_token TEXT,
            generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (script_id) REFERENCES scripts(id)
        );

        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `;
    
    db.exec(createTables);

    // Create default admin
    const adminCheck = db.prepare('SELECT * FROM admin_users WHERE username = ?');
    const adminExists = adminCheck.get(process.env.ADMIN_USERNAME || 'admin');
    
    if (!adminExists) {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'SecurePassword123!', salt);
        const insert = db.prepare('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)');
        insert.run(process.env.ADMIN_USERNAME || 'admin', hash);
        console.log('✅ Default admin user created');
    }
    
    console.log('✅ Database initialized');
};

initDb();

// Auth middleware
const authenticateAdmin = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_super_secret_key_here_change_me');
        req.admin = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// ===================== PUBLIC ENDPOINTS =====================

// Get scripts by category
app.get('/api/scripts', (req, res) => {
    try {
        const { category } = req.query;
        let query = 'SELECT id, title, description, category, image_url, display_likes, display_downloads FROM scripts';
        let params = [];

        if (category && category !== 'all') {
            query += ' WHERE category = ?';
            params.push(category);
        }

        query += ' ORDER BY created_at DESC';
        
        const stmt = db.prepare(query);
        const scripts = stmt.all(...params);
        res.json(scripts);
    } catch (error) {
        console.error('Error fetching scripts:', error);
        res.status(500).json({ error: 'Failed to fetch scripts' });
    }
});

// Get single script
app.get('/api/scripts/:id', (req, res) => {
    try {
        const stmt = db.prepare('SELECT * FROM scripts WHERE id = ?');
        const script = stmt.get(req.params.id);
        
        if (!script) {
            return res.status(404).json({ error: 'Script not found' });
        }
        
        res.json(script);
    } catch (error) {
        console.error('Error fetching script:', error);
        res.status(500).json({ error: 'Failed to fetch script' });
    }
});

// Get loadstring by ID
app.get('/api/loadstrings/:id', (req, res) => {
    try {
        const { id } = req.params;
        
        const stmt = db.prepare(`
            SELECT script_id, actual_loadstring, expires_at, is_active 
            FROM loadstrings 
            WHERE id = ?
        `);
        const loadstring = stmt.get(id);
        
        if (!loadstring) {
            return res.status(404).json({ error: 'Loadstring not found' });
        }
        
        if (!loadstring.is_active) {
            return res.status(403).json({ error: 'This loadstring has been deactivated' });
        }
        
        const now = new Date();
        const expires = new Date(loadstring.expires_at);
        
        if (now > expires) {
            const deactivate = db.prepare('UPDATE loadstrings SET is_active = 0 WHERE id = ?');
            deactivate.run(id);
            return res.status(403).json({ error: 'This loadstring has expired. Please generate a new one.' });
        }
        
        res.json({
            script: loadstring.actual_loadstring,
            expires_at: loadstring.expires_at
        });
    } catch (error) {
        console.error('Error fetching loadstring:', error);
        res.status(500).json({ error: 'Failed to fetch loadstring' });
    }
});

// Generate loadstring
app.post('/api/generate-loadstring', (req, res) => {
    try {
        const { script_id, key_token } = req.body;
        
        if (!script_id || !key_token) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const keyCheck = db.prepare(`
            SELECT id, script_id, is_used, expires_at 
            FROM redeemed_keys 
            WHERE key_token = ? AND is_used = 0
        `);
        const redeemedKey = keyCheck.get(key_token);
        
        if (!redeemedKey) {
            return res.status(400).json({ error: 'Invalid or already used key token' });
        }
        
        if (redeemedKey.expires_at) {
            const now = new Date();
            const expires = new Date(redeemedKey.expires_at);
            if (now > expires) {
                return res.status(400).json({ error: 'Key has expired' });
            }
        }
        
        const scriptStmt = db.prepare('SELECT actual_loadstring FROM scripts WHERE id = ?');
        const script = scriptStmt.get(script_id);
        
        if (!script) {
            return res.status(404).json({ error: 'Script not found' });
        }
        
        const loadstringId = uuidv4().slice(0, 10);
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        const insert = db.prepare(`
            INSERT INTO loadstrings (id, script_id, actual_loadstring, key_token, expires_at)
            VALUES (?, ?, ?, ?, ?)
        `);
        insert.run(loadstringId, script_id, script.actual_loadstring, key_token, expiresAt.toISOString());
        
        const updateKey = db.prepare('UPDATE redeemed_keys SET is_used = 1 WHERE key_token = ?');
        updateKey.run(key_token);
        
        const baseUrl = process.env.BASE_URL || `https://xmithub-api.onrender.com`;
        
        res.json({
            success: true,
            loadstring_url: `${baseUrl}/api/loadstrings/${loadstringId}`,
            loadstring_code: `
-- XmitScript Hub Loadstring
-- Generated: ${new Date().toISOString()}
-- Expires: ${expiresAt.toISOString()}

local loadstringUrl = "${baseUrl}/api/loadstrings/${loadstringId}"
local response = game:HttpGet(loadstringUrl)
local data = game:GetService("HttpService"):JSONDecode(response)
if data.script then
    loadstring(data.script)()
else
    warn("Failed to load script: " .. (data.error or "Unknown error"))
end
            `.trim(),
            expires_at: expiresAt.toISOString()
        });
    } catch (error) {
        console.error('Error generating loadstring:', error);
        res.status(500).json({ error: 'Failed to generate loadstring' });
    }
});

// Redeem work.ink key
app.post('/api/redeem-key', (req, res) => {
    try {
        const { workink_key, script_id } = req.body;
        
        if (!workink_key) {
            return res.status(400).json({ error: 'Key is required' });
        }
        
        const keyCheck = db.prepare('SELECT * FROM redeemed_keys WHERE workink_key = ?');
        const existingKey = keyCheck.get(workink_key);
        
        if (existingKey) {
            if (existingKey.is_used) {
                return res.status(400).json({ error: 'This key has already been used' });
            }
            return res.json({
                success: true,
                key_token: existingKey.key_token,
                message: 'Key verified successfully'
            });
        }
        
        const keyToken = uuidv4();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        const insert = db.prepare(`
            INSERT INTO redeemed_keys (workink_key, script_id, key_token, expires_at)
            VALUES (?, ?, ?, ?)
        `);
        insert.run(workink_key, script_id || null, keyToken, expiresAt.toISOString());
        
        res.json({
            success: true,
            key_token: keyToken,
            expires_at: expiresAt.toISOString(),
            message: 'Key redeemed successfully'
        });
    } catch (error) {
        console.error('Error redeeming key:', error);
        res.status(500).json({ error: 'Failed to redeem key' });
    }
});

// ===================== ADMIN ENDPOINTS =====================

// Admin login
app.post('/api/admin/login', (req, res) => {
    try {
        const { username, password } = req.body;
        
        const stmt = db.prepare('SELECT * FROM admin_users WHERE username = ?');
        const user = stmt.get(username);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const isValid = bcrypt.compareSync(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET || 'your_super_secret_key_here_change_me',
            { expiresIn: '24h' }
        );
        
        res.json({ token, username: user.username });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get all scripts (admin)
app.get('/api/admin/scripts', authenticateAdmin, (req, res) => {
    try {
        const stmt = db.prepare('SELECT * FROM scripts ORDER BY created_at DESC');
        const scripts = stmt.all();
        res.json(scripts);
    } catch (error) {
        console.error('Error fetching admin scripts:', error);
        res.status(500).json({ error: 'Failed to fetch scripts' });
    }
});

// Create script (admin)
app.post('/api/admin/scripts', authenticateAdmin, (req, res) => {
    try {
        const { title, description, category, image_url, actual_loadstring, display_likes, display_downloads } = req.body;
        
        if (!title || !category || !actual_loadstring) {
            return res.status(400).json({ error: 'Title, category, and loadstring are required' });
        }
        
        const validCategories = ['rivals', 'arsenal', 'overkill', 'universal'];
        if (!validCategories.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        
        const insert = db.prepare(`
            INSERT INTO scripts (title, description, category, image_url, actual_loadstring, display_likes, display_downloads)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        const result = insert.run(
            title,
            description || '',
            category,
            image_url || '',
            actual_loadstring,
            display_likes || 0,
            display_downloads || 0
        );
        
        const getStmt = db.prepare('SELECT * FROM scripts WHERE id = ?');
        const script = getStmt.get(result.lastInsertRowid);
        
        res.json({ success: true, script });
    } catch (error) {
        console.error('Error creating script:', error);
        res.status(500).json({ error: 'Failed to create script' });
    }
});

// Update script (admin)
app.put('/api/admin/scripts/:id', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, category, image_url, actual_loadstring, display_likes, display_downloads } = req.body;
        
        const validCategories = ['rivals', 'arsenal', 'overkill', 'universal'];
        if (category && !validCategories.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        
        const update = db.prepare(`
            UPDATE scripts 
            SET title = ?, description = ?, category = ?, image_url = ?, 
                actual_loadstring = ?, display_likes = ?, display_downloads = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `);
        const result = update.run(
            title,
            description || '',
            category,
            image_url || '',
            actual_loadstring,
            display_likes || 0,
            display_downloads || 0,
            id
        );
        
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Script not found' });
        }
        
        const getStmt = db.prepare('SELECT * FROM scripts WHERE id = ?');
        const script = getStmt.get(id);
        
        res.json({ success: true, script });
    } catch (error) {
        console.error('Error updating script:', error);
        res.status(500).json({ error: 'Failed to update script' });
    }
});

// Delete script (admin)
app.delete('/api/admin/scripts/:id', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        
        const deleteLoadstrings = db.prepare('DELETE FROM loadstrings WHERE script_id = ?');
        deleteLoadstrings.run(id);
        
        const deleteScript = db.prepare('DELETE FROM scripts WHERE id = ?');
        const result = deleteScript.run(id);
        
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Script not found' });
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting script:', error);
        res.status(500).json({ error: 'Failed to delete script' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 XmitScript Hub API running on port ${PORT}`);
    console.log(`🌐 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
