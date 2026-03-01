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

// server.js
// Minimal auth service with SQLite, sessions, protected route
// Install deps first:
//   npm init -y
//   npm install express sqlite3 express-session bcryptjs

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Database initialization ----------

const DB_PATH = path.join(__dirname, 'auth.db');
const db = new sqlite3.Database(DB_PATH);

// Create users table if it doesn't exist
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
        console.log('Users table ready');
      }
    }
  );
});

// ---------- Middleware configuration ----------

app.use(express.json());

app.use(
  session({
    name: 'sid',
    secret: 'replace_this_with_a_long_random_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// Session verification middleware
function requireSession(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({
    success: false,
    message: 'Invalid or missing session. Access denied.',
  });
}

// ---------- Helper functions ----------

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

// ---------- Routes ----------

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Auth service running' });
});

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password || password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Username and password (min 6 chars) are required.',
      });
    }

    const existing = await findUserByUsername(username);
    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'Username already taken.',
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await createUser(username, passwordHash);

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({
      success: false,
      message: 'Internal server error during registration.',
    });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required.',
      });
    }

    const user = await findUserByUsername(username);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.',
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.',
      });
    }

    // Establish session and store relevant user info
    req.session.user = {
      id: user.id,
      username: user.username,
      loginAt: new Date().toISOString(),
    };

    return res.json({
      success: true,
      message: 'Login successful. Session established.',
      user: req.session.user,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({
      success: false,
      message: 'Internal server error during login.',
    });
  }
});

// Protected route
app.get('/protected', requireSession, (req, res) => {
  // If middleware passes, session is valid
  return res.json({
    success: true,
    message: 'Session verification successful. Access granted.',
    user: req.session.user,
  });
});

// Logout endpoint
app.post('/logout', (req, res) => {
  if (!req.session) {
    return res.status(200).json({
      success: true,
      message: 'No active session.',
    });
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({
        success: false,
        message: 'Error while logging out.',
      });
    }

    res.clearCookie('sid');
    return res.json({
      success: true,
      message: 'Logged out and session destroyed.',
    });
  });
});

// Fallback for unknown routes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found.',
  });
});

// ---------- Application startup ----------

app.listen(PORT, () => {
  console.log(`Auth service listening on http://localhost:${PORT}`);
});
