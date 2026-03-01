/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Chaptgpt-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: postgresql
Prompt Used:
"Create a standalone authentication backend using JavaScript that implements session-based authentication. The application should connect to a relational database containing user records.
After successful login, the server should create a session and associate it with the authenticated user. Implement at least one protected endpoint that can only be accessed if a valid session exists. If a request is made without an active session, access should be denied.
Provide complete backend code including session configuration, middleware for session checking, database connection setup, and server initialization."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);

const app = express();

/* ===============================
   Database Connection
================================ */
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

pool.connect()
  .then(() => console.log('Connected to PostgreSQL'))
  .catch(err => console.error('DB connection error:', err));

/* ===============================
   Middleware
================================ */
app.use(express.json());

/* ===============================
   Session Configuration
================================ */
app.use(
  session({
    store: new pgSession({
      pool: pool,
      tableName: 'session',
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60, // 1 hour
      httpOnly: true,
      secure: false, // set true in production (HTTPS)
    },
  })
);

/* ===============================
   Authentication Middleware
================================ */
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  return res.status(401).json({
    success: false,
    message: 'Access denied. Please login.',
  });
}

/* ===============================
   Routes
================================ */

/* ---- Register (Optional) ---- */
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Registration failed',
    });
  }
});

/* ---- Login ---- */
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      message: 'Login successful',
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
    });
  }
});

/* ---- Protected Route ---- */
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.json({
    success: true,
    message: `Welcome ${req.session.username}`,
    userId: req.session.userId,
  });
});

/* ---- Logout ---- */
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Logout failed',
      });
    }

    res.clearCookie('connect.sid');

    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  });
});

/* ---- Public Route ---- */
app.get('/', (req, res) => {
  res.json({
    message: 'Session-Based Authentication API Running',
  });
});

/* ===============================
   Server Initialization
================================ */
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});