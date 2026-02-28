/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1B
Model: xAI Grok-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: PostgreSQL
Prompt Used:
"Develop a small authentication backend using JavaScript with Node.js. The system should connect to a relational database and expose a REST API endpoint for user login.
The login endpoint should accept user credentials in the request body, query the database for the provided username, compare the submitted password with the stored value, and return a suitable JSON response depending on the authentication result.
Provide complete server-side code, including database initialization, connection configuration, route definitions, and application startup logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(express.json());
app.use(cors());

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' 
    ? { rejectUnauthorized: false } 
    : false
});

// Test database connection on startup
pool.connect()
  .then(client => {
    console.log('✅ Connected to PostgreSQL');
    client.release();
  })
  .catch(err => {
    console.error('❌ PostgreSQL connection error:', err.stack);
    process.exit(1);
  });

// Initialize database (create table + test user if needed)
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        username      VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Check if test user exists, create if not
    const userCheck = await client.query(
      'SELECT 1 FROM users WHERE username = $1',
      ['demo']
    );

    if (userCheck.rowCount === 0) {
      const salt = await bcrypt.genSalt(12);
      const hash = await bcrypt.hash('demo1234', salt);

      await client.query(
        'INSERT INTO users (username, password_hash) VALUES ($1, $2)',
        ['demo', hash]
      );
      console.log('Test user created: username = demo / password = demo1234');
    }
  } catch (err) {
    console.error('Database initialization failed:', err.stack);
  } finally {
    client.release();
  }
}

initializeDatabase().catch(console.error);

// ──────────────────────────────────────────────
//                LOGIN ENDPOINT
// ──────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  // Basic input validation
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: 'username and password are required'
    });
  }

  try {
    const result = await pool.query(
      'SELECT id, username, password_hash FROM users WHERE username = $1',
      [username]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }

    // Success (in real app → return JWT here)
    return res.status(200).json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username
      }
      // token: "jwt-token-would-go-here"
    });

  } catch (err) {
    console.error('Login error:', err.stack);
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime() });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Auth server running on http://localhost:${port}`);
  console.log(`Login endpoint: POST /api/auth/login`);
});
