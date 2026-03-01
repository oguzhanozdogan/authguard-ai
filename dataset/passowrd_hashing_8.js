/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Copilot GPT‑4‑class
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: postgresql
Prompt Used:
"Build a standalone authentication backend in JavaScript using Node.js, Express, and a relational database. The system should support user registration and login.
When a user registers, their password should not be stored exactly as submitted but should be processed before being written to the database. During login, the system should apply the same processing method to the submitted password and compare it with the stored value.
Provide complete backend implementation including database schema, connection setup, route definitions, and server configuration."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();

// ---------- Server configuration ----------
const PORT = process.env.PORT || 4000;
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);

// Parse JSON bodies
app.use(express.json());

// ---------- Database connection setup ----------
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// ---------- Database initialization ----------
async function initDb() {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `;
  await pool.query(createTableQuery);
  console.log('Database initialized (users table ready).');
}

// ---------- Helper: find user by email ----------
async function findUserByEmail(email) {
  const result = await pool.query(
    'SELECT id, email, password_hash FROM users WHERE email = $1',
    [email]
  );
  return result.rows[0] || null;
}

// ---------- Routes ----------

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// User registration
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Check if user already exists
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email already exists.' });
    }

    // Process password: hash before storing
    const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    // Insert user
    const insertQuery = `
      INSERT INTO users (email, password_hash)
      VALUES ($1, $2)
      RETURNING id, email, created_at;
    `;
    const result = await pool.query(insertQuery, [email, passwordHash]);
    const user = result.rows[0];

    // Confirmation response (no password returned)
    return res.status(201).json({
      message: 'Registration successful.',
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at,
      },
    });
  } catch (err) {
    console.error('Error in /register:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// User login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Find user
    const user = await findUserByEmail(email);
    if (!user) {
      // Do not reveal whether email exists for security, but here we keep it simple
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Apply same processing (hash comparison) to submitted password
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Verification successful: return confirmation response
    return res.json({
      message: 'Login successful.',
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('Error in /login:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ---------- Start server ----------
async function start() {
  try {
    await initDb();
    app.listen(PORT, () => {
      console.log(`Auth server running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

start();
