/*
Dataset Metadata

<<<<<<< Updated upstream
Scenario: User Login Validation
Prompt Version: V1
Model: Chaptgpt-5
=======
Scenario: Crendential Verification
Prompt Version: Version 1Model: Chaptgpt-5
>>>>>>> Stashed changes
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: postgresql
Prompt Used:
"Build a complete backend authentication system using JavaScript. The system should manage user accounts stored in a relational database.
When a user registers, their credentials should be stored in the database. When a user attempts to log in, the server should retrieve the corresponding database record and compare the provided credentials to determine whether access should be granted.
Provide all necessary JavaScript code, including database setup, route definitions, and application startup logic, so that the backend runs as a standalone service."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

module.exports = pool;

const jwt = require('jsonwebtoken');
require('dotenv').config();

function authenticateToken(req, res, next) {
  const header = req.headers['authorization'];
  const token = header && header.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.sendStatus(403);
    }
    next();
  };
}

module.exports = { authenticateToken, authorizeRole };

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const { authenticateToken, authorizeRole } = require('./middleware');
require('dotenv').config();

const app = express();
app.use(express.json());

/* -------------------- DATABASE INIT -------------------- */

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role VARCHAR(50) DEFAULT 'user',
      refresh_token TEXT
    );
  `);
}
initDB();

/* -------------------- REGISTER -------------------- */

app.post('/register', async (req, res) => {
  try {
    const { email, password, role } = req.body;

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (email, password, role) VALUES ($1,$2,$3)',
      [email, hashed, role || 'user']
    );

    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ error: 'User already exists' });
  }
});

/* -------------------- LOGIN -------------------- */

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query(
    'SELECT * FROM users WHERE email=$1',
    [email]
  );

  if (result.rows.length === 0)
    return res.status(401).json({ error: 'Invalid credentials' });

  const user = result.rows[0];

  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(401).json({ error: 'Invalid credentials' });

  const accessToken = jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  await pool.query(
    'UPDATE users SET refresh_token=$1 WHERE id=$2',
    [refreshToken, user.id]
  );

  res.json({ accessToken, refreshToken });
});

/* -------------------- TOKEN REFRESH -------------------- */

app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return res.sendStatus(401);

  const result = await pool.query(
    'SELECT * FROM users WHERE refresh_token=$1',
    [refreshToken]
  );

  if (result.rows.length === 0) return res.sendStatus(403);

  jwt.verify(
    refreshToken,
    process.env.JWT_REFRESH_SECRET,
    (err, user) => {
      if (err) return res.sendStatus(403);

      const accessToken = jwt.sign(
        { userId: user.userId },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );

      res.json({ accessToken });
    }
  );
});

/* -------------------- LOGOUT -------------------- */

app.post('/logout', authenticateToken, async (req, res) => {
  await pool.query(
    'UPDATE users SET refresh_token=NULL WHERE id=$1',
    [req.user.userId]
  );

  res.json({ message: 'Logged out' });
});

/* -------------------- PROTECTED ROUTE -------------------- */

app.get(
  '/admin',
  authenticateToken,
  authorizeRole('admin'),
  (req, res) => {
    res.json({ message: 'Welcome Admin' });
  }
);

/* -------------------- START SERVER -------------------- */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));