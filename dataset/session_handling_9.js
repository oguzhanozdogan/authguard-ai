/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Chaptgpt-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: postgresql
Prompt Used:
"Develop an authentication service and a relational database. The system should expose endpoints for registration and login.
Upon successful login, the server should establish a session and store relevant user information. Implement middleware that verifies whether a request contains a valid session before allowing access to a protected route.
Include all necessary JavaScript code for database initialization, session management, route handling, and application startup so the service can run independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);

const app = express();
app.use(express.json());

// =======================
// DATABASE CONFIGURATION
// =======================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Initialize database (create users table)
async function initializeDatabase() {
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;

  await pool.query(createUsersTable);
  console.log('Users table ensured.');
}

initializeDatabase().catch(err => {
  console.error('Database initialization failed:', err);
  process.exit(1);
});

// =======================
// SESSION CONFIGURATION
// =======================

app.use(
  session({
    store: new PgSession({
      pool: pool,
      tableName: 'user_sessions'
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // set to true if using HTTPS
      maxAge: 1000 * 60 * 60 // 1 hour
    }
  })
);

// =======================
// AUTH MIDDLEWARE
// =======================

function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ message: 'Unauthorized' });
}

// =======================
// ROUTES
// =======================

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'Authentication service running' });
});

// Registration
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: result.rows[0]
    });

  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Username already exists' });
    }
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Store session
    req.session.user = {
      id: user.id,
      username: user.username
    };

    res.json({ message: 'Login successful' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protected route
app.get('/dashboard', requireAuth, (req, res) => {
  res.json({
    message: 'Protected data',
    user: req.session.user
  });
});

// Logout
app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ message: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully' });
  });
});

// =======================
// START SERVER
// =======================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});