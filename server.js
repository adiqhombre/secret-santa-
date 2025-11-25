const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

// Admin password hash (password: Santa2025!)
// Pre-hashed for security - generated with bcrypt.hashSync('Santa2025!', 10)
const ADMIN_PASSWORD_HASH = '$2b$10$QiiFsp/N4rOLdrQ6e782Te2pIptAN.F4BuPsJvxvKawfjviNi3jim';

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
  app.use(cors({
    origin: [
      'http://localhost:3000',
      'https://secret-santa-frontend-navy.vercel.app' // Replace with your actual Vercel URL
    ],
    credentials: true
  }));
app.use(express.json());

// Initialize database tables
const initDB = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
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

    console.log('Database tables initialized');
  } catch (err) {
    console.error('Error initializing database:', err);
  } finally {
    client.release();
  }
};

initDB();

// API Routes

// Get all users (admin only - no passwords)
app.get('/api/users', async (req, res) => {
  const { family_code } = req.query;

  if (!family_code) {
    return res.status(400).json({ error: 'family_code is required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, name FROM users WHERE family_code = $1 ORDER BY name',
      [family_code]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add a new user
app.post('/api/users', async (req, res) => {
  const { name, password, family_code } = req.body;

  if (!name || !password || !family_code) {
    return res.status(400).json({ error: 'Name, password, and family_code required' });
  }

  try {
    // Hash the password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (name, password, family_code) VALUES ($1, $2, $3) RETURNING id, name',
      [name, hashedPassword, family_code]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') { // Unique violation
      res.status(400).json({ error: 'User already exists' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  }
});

// Delete a user
app.delete('/api/users/:name', async (req, res) => {
  const { name } = req.params;
  const { family_code } = req.query;

  if (!family_code) {
    return res.status(400).json({ error: 'family_code is required' });
  }

  try {
    // Also delete their assignment
    await pool.query(
      'DELETE FROM assignments WHERE (giver = $1 OR receiver = $1) AND family_code = $2',
      [name, family_code]
    );
    await pool.query('DELETE FROM users WHERE name = $1 AND family_code = $2', [name, family_code]);
    res.json({ message: 'User deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Get user by username (including password hash and family_code)
    const result = await pool.query(
      'SELECT id, name, password, family_code FROM users WHERE LOWER(name) = LOWER($1)',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Compare provided password with stored hash
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Return user without password but with family_code
    res.json({ user: { id: user.id, name: user.name, family_code: user.family_code } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin verification
app.post('/api/admin/verify', async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  try {
    const isValid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Generate assignments
app.post('/api/assignments/generate', async (req, res) => {
  const { family_code } = req.body;

  if (!family_code) {
    return res.status(400).json({ error: 'family_code is required' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Get all users for this family
    const usersResult = await client.query(
      'SELECT name FROM users WHERE family_code = $1 ORDER BY name',
      [family_code]
    );
    const users = usersResult.rows.map(u => u.name);

    if (users.length < 2) {
      return res.status(400).json({ error: 'Need at least 2 users' });
    }

    // Generate random derangement (no one gets themselves)
    let givers = [...users];
    let receivers = [...users];

    // Fisher-Yates shuffle
    for (let i = receivers.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [receivers[i], receivers[j]] = [receivers[j], receivers[i]];
    }

    // Ensure no one got themselves (try up to 100 times)
    let attempts = 0;
    while (attempts < 100) {
      let valid = true;
      for (let i = 0; i < givers.length; i++) {
        if (givers[i] === receivers[i]) {
          valid = false;
          break;
        }
      }

      if (valid) break;

      // Reshuffle
      for (let i = receivers.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [receivers[i], receivers[j]] = [receivers[j], receivers[i]];
      }
      attempts++;
    }

    // Clear existing assignments for this family
    await client.query('DELETE FROM assignments WHERE family_code = $1', [family_code]);

    // Insert new assignments
    for (let i = 0; i < givers.length; i++) {
      await client.query(
        'INSERT INTO assignments (giver, receiver, family_code) VALUES ($1, $2, $3)',
        [givers[i], receivers[i], family_code]
      );
    }

    // Set assignments generated flag for this family
    await client.query(`
      INSERT INTO settings (key, value, family_code)
      VALUES ('assignments_generated', 'true', $1)
      ON CONFLICT (key, family_code) DO UPDATE SET value = 'true'
    `, [family_code]);

    await client.query('COMMIT');
    res.json({ message: 'Assignments generated successfully' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// Get assignment for a user
app.get('/api/assignments/:username', async (req, res) => {
  const { username } = req.params;
  const { family_code } = req.query;

  if (!family_code) {
    return res.status(400).json({ error: 'family_code is required' });
  }

  try {
    // Check if assignments are generated for this family
    const settingsResult = await pool.query(
      "SELECT value FROM settings WHERE key = 'assignments_generated' AND family_code = $1",
      [family_code]
    );

    if (settingsResult.rows.length === 0 || settingsResult.rows[0].value !== 'true') {
      return res.status(400).json({ error: 'Assignments not generated yet' });
    }

    const result = await pool.query(
      'SELECT receiver FROM assignments WHERE giver = $1 AND family_code = $2',
      [username, family_code]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No assignment found' });
    }

    res.json({ receiver: result.rows[0].receiver });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check if assignments are generated
app.get('/api/assignments/status', async (req, res) => {
  const { family_code } = req.query;

  if (!family_code) {
    return res.status(400).json({ error: 'family_code is required' });
  }

  try {
    const result = await pool.query(
      "SELECT value FROM settings WHERE key = 'assignments_generated' AND family_code = $1",
      [family_code]
    );

    const generated = result.rows.length > 0 && result.rows[0].value === 'true';
    res.json({ generated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset everything for a specific family
app.post('/api/reset', async (req, res) => {
  const { family_code } = req.body;

  if (!family_code) {
    return res.status(400).json({ error: 'family_code is required' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM assignments WHERE family_code = $1', [family_code]);
    await client.query('DELETE FROM users WHERE family_code = $1', [family_code]);
    await client.query('DELETE FROM settings WHERE family_code = $1', [family_code]);
    await client.query('COMMIT');
    res.json({ message: 'Family data reset' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(port, () => {
  console.log(`Secret Santa API running on port ${port}`);
});