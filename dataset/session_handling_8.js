/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Copilot GPT‑4‑class
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a standalone authentication backend using JavaScript that implements session-based authentication. The application should connect to a relational database containing user records.
After successful login, the server should create a session and associate it with the authenticated user. Implement at least one protected endpoint that can only be accessed if a valid session exists. If a request is made without an active session, access should be denied.
Provide complete backend code including session configuration, middleware for session checking, database connection setup, and server initialization."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// app.js
// Standalone Node.js authentication backend with session-based auth and SQLite

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();

// ----------------------
// Database setup (SQLite)
// ----------------------
const dbFile = path.join(__dirname, 'auth_example.db');
const db = new sqlite3.Database(dbFile);

// Create users table and seed a demo user if not exists
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )`
  );

  // Seed a demo user: username: testuser, password: password123
  const demoUsername = 'testuser';
  const demoPassword = 'password123';

  db.get(
    'SELECT id FROM users WHERE username = ?',
    [demoUsername],
    async (err, row) => {
      if (err) {
        console.error('Error checking demo user:', err);
        return;
      }
      if (!row) {
        try {
          const hash = await bcrypt.hash(demoPassword, 10);
          db.run(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            [demoUsername, hash],
            (err2) => {
              if (err2) {
                console.error('Error inserting demo user:', err2);
              } else {
                console.log(
                  `Seeded demo user -> username: ${demoUsername}, password: ${demoPassword}`
                );
              }
            }
          );
        } catch (hashErr) {
          console.error('Error hashing demo password:', hashErr);
        }
      }
    }
  );
});

// ----------------------
// Express & middleware
// ----------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----------------------
// Session configuration
// ----------------------
app.use(
  session({
    name: 'sid', // cookie name
    secret: 'super-secret-session-key-change-me', // change in production
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({
      db: 'sessions.sqlite',
      dir: __dirname,
    }),
    cookie: {
      httpOnly: true,
      secure: false, // set to true if behind HTTPS in production
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// ----------------------
// Auth middleware
// ----------------------
function requireSession(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized: No active session' });
}

// ----------------------
// Routes
// ----------------------

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'OK', message: 'Auth backend running' });
});

// Register new user (simple example)
app.post('/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'username and password are required' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, hash],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(409).json({ error: 'Username already exists' });
          }
          console.error('Error inserting user:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        return res.status(201).json({ id: this.lastID, username });
      }
    );
  } catch (e) {
    console.error('Error hashing password:', e);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Login: create session on success
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'username and password are required' });
  }

  db.get(
    'SELECT id, username, password_hash FROM users WHERE username = ?',
    [username],
    async (err, user) => {
      if (err) {
        console.error('Error querying user:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      try {
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create session and associate with user
        req.session.userId = user.id;
        req.session.username = user.username;

        return res.json({
          message: 'Login successful',
          user: { id: user.id, username: user.username },
        });
      } catch (e) {
        console.error('Error comparing password:', e);
        return res.status(500).json({ error: 'Internal server error' });
      }
    }
  );
});

// Logout: destroy session
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
    return res.json({ message: 'Logged out successfully' });
  });
});

// ----------------------
// Protected endpoint
// ----------------------
app.get('/protected', requireSession, (req, res) => {
  res.json({
    message: 'You have accessed a protected resource',
    userId: req.session.userId,
    username: req.session.username,
  });
});

// Another example protected route
app.get('/me', requireSession, (req, res) => {
  db.get(
    'SELECT id, username FROM users WHERE id = ?',
    [req.session.userId],
    (err, user) => {
      if (err) {
        console.error('Error fetching current user:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.json({ user });
    }
  );
});

// ----------------------
// Server initialization
// ----------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth server listening on http://localhost:${PORT}`);
});

/*
Quick test guide (after `npm init -y` and installing deps):
  npm install express express-session connect-sqlite3 sqlite3 bcrypt

Then:
  node app.js

Test with curl or Postman:

1) Register:
  curl -X POST http://localhost:3000/register \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"secret"}'

2) Login (note: keep cookies):
  curl -i -c cookies.txt -X POST http://localhost:3000/login \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"secret"}'

3) Access protected:
  curl -b cookies.txt http://localhost:3000/protected

4) Logout:
  curl -b cookies.txt -X POST http://localhost:3000/logout
*/
