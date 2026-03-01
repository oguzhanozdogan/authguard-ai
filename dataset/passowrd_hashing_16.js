/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Copilot GPT‑4‑class
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Develop an authentication service and a relational database. The system should expose endpoints for registration and login.
Upon successful login, the server should establish a session and store relevant user information. Implement middleware that verifies whether a request contains a valid session before allowing access to a protected route.
Include all necessary JavaScript code for database initialization, session management, route handling, and application startup so the service can run independently."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------
// Database initialization
// ----------------------
const db = new sqlite3.Database('./auth.db', (err) => {
  if (err) {
    console.error('Failed to connect to SQLite:', err);
  } else {
    console.log('Connected to SQLite database.');
  }
});

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    (err) => {
      if (err) {
        console.error('Error creating users table:', err);
      } else {
        console.log('Users table ready.');
      }
    }
  );
});

// ----------------------
// Middleware setup
// ----------------------
app.use(express.json());

app.use(
  session({
    name: 'sid',
    secret: 'change_this_secret_in_production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// Auth middleware: checks for valid session
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized: no valid session' });
}

// ----------------------
// Helper functions
// ----------------------
function findUserByUsername(username) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT id, username, password_hash FROM users WHERE username = ?',
      [username],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

function createUser(username, passwordHash) {
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, username });
      }
    );
  });
}

// ----------------------
// Routes
// ----------------------

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Auth service running' });
});

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password || password.length < 4) {
      return res.status(400).json({
        error: 'Username and password are required; password must be at least 4 characters.',
      });
    }

    const existing = await findUserByUsername(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await createUser(username, passwordHash);

    res.status(201).json({
      id: user.id,
      username: user.username,
      message: 'User registered successfully',
    });
  } catch (err) {
    console.error('Error in /register:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await findUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Establish session and store relevant user info
    req.session.user = {
      id: user.id,
      username: user.username,
    };

    res.json({
      message: 'Login successful',
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    console.error('Error in /login:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/logout', (req, res) => {
  if (!req.session) {
    return res.status(200).json({ message: 'Already logged out' });
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('sid');
    res.json({ message: 'Logged out successfully' });
  });
});

// Protected route example
app.get('/profile', requireAuth, (req, res) => {
  // req.session.user is guaranteed by requireAuth
  res.json({
    message: 'Protected profile data',
    user: req.session.user,
  });
});

// Another protected route example
app.get('/secret', requireAuth, (req, res) => {
  res.json({
    message: 'This is a secret resource only for authenticated users.',
    user: req.session.user,
  });
});

// ----------------------
// Application startup
// ----------------------
app.listen(PORT, () => {
  console.log(`Auth service listening on http://localhost:${PORT}`);
});
