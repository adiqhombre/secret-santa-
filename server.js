const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

const JWT_SECRET = process.env.JWT_SECRET;

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors());
app.use(express.json());

// ---------------------
// AUTH MIDDLEWARE
// ---------------------

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }

  try {
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, name, role }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admins only' });
  }
  next();
}

// ---------------------
// INIT DATABASE
// ---------------------

const initDB = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS assignments (
        id SERIAL PRIMARY KEY,
        giver VARCHAR(255) NOT NULL,
        receiver VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(giver)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS settings (
        id SERIAL PRIMARY KEY,
        key VARCHAR(255) UNIQUE NOT NULL,
        value TEXT NOT NULL
      );
    `);

    // Ensure Admin user exists
    const adminCheck = await client.query(`SELECT * FROM users WHERE name='admin'`);
    if (adminCheck.rows.length === 0) {
      const hashed = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      await client.query(
        `INSERT INTO users (name, password, role) VALUES ($1, $2, $3)`,
        ['admin', hashed, 'admin']
      );
      console.log('Admin user created.');
    }

    console.log('Database initialized');
  } catch (err) {
    console.error('DB error:', err);
  } finally {
    client.release();
  }
};

initDB();

// ---------------------
// AUTH ROUTES
// ---------------------

// LOGIN
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(name) = LOWER($1)',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ 
      token,
      user: { id: user.id, name: user.name, role: user.role }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------
// USER MANAGEMENT (ADMIN ONLY)
// ---------------------

app.get('/api/users', auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, role FROM users ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { name, password } = req.body;

  if (!name || !password)
    return res.status(400).json({ error: 'Name and password required' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (name, password) VALUES ($1, $2) RETURNING id, name, role',
      [name, hashedPassword]
    );

    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).json({ error: 'User already exists' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  }
});

app.delete('/api/users/:name', auth, adminOnly, async (req, res) => {
  const { name } = req.params;

  try {
    await pool.query('DELETE FROM assignments WHERE giver=$1 OR receiver=$1', [name]);
    await pool.query('DELETE FROM users WHERE name=$1', [name]);
    res.json({ message: 'User deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------
// ASSIGNMENTS
// ---------------------

// Generate assignments (ADMIN ONLY)
app.post('/api/assignments/generate', auth, adminOnly, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const usersResult = await client.query('SELECT name FROM users ORDER BY name');
    const users = usersResult.rows.map(u => u.name);

    if (users.length < 2)
      return res.status(400).json({ error: 'Need at least 2 users' });

    let givers = [...users];
    let receivers = [...users];

    // Shuffle receivers
    for (let i = receivers.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [receivers[i], receivers[j]] = [receivers[j], receivers[i]];
    }

    // Ensure no one gets themself
    let attempts = 0;
    while (attempts < 100) {
      let valid = true;
      for (let i = 0; i < givers.length; i++) {
        if (givers[i] === receivers[i]) valid = false;
      }
      if (valid) break;

      for (let i = receivers.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [receivers[i], receivers[j]] = [receivers[j], receivers[i]];
      }
      attempts++;
    }

    await client.query('DELETE FROM assignments');

    for (let i = 0; i < givers.length; i++) {
      await client.query(
        'INSERT INTO assignments (giver, receiver) VALUES ($1, $2)',
        [givers[i], receivers[i]]
      );
    }

    await client.query(`
      INSERT INTO settings (key, value)
      VALUES ('assignments_generated', 'true')
      ON CONFLICT (key) DO UPDATE SET value='true'
    `);

    await client.query('COMMIT');
    res.json({ message: 'Assignments generated' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// GET assignment for logged-in user
app.get('/api/assignments/me', auth, async (req, res) => {
  const username = req.user.name;

  try {
    const set = await pool.query(
      "SELECT value FROM settings WHERE key='assignments_generated'"
    );

    if (set.rows.length === 0 || set.rows[0].value !== 'true')
      return res.status(400).json({ error: 'Assignments not generated yet' });

    const result = await pool.query(
      'SELECT receiver FROM assignments WHERE giver=$1',
      [username]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ error: 'No assignment found' });

    res.json({ receiver: result.rows[0].receiver });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check if assignments generated
app.get('/api/assignments/status', auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT value FROM settings WHERE key = 'assignments_generated'"
    );
    res.json({ generated: result.rows.length > 0 && result.rows[0].value === 'true' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------
// RESET (ADMIN ONLY)
// ---------------------

app.post('/api/reset', auth, adminOnly, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM assignments');
    await client.query('DELETE FROM users WHERE name != $1', ['admin']);
    await client.query('DELETE FROM settings');
    await client.query('COMMIT');
    res.json({ message: 'System reset' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// ---------------------

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ---------------------

app.listen(port, () => {
  console.log(`Secret Santa API running on port ${port}`);
});
