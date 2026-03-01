/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Copilot GPT4-class
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Implement a standalone authentication backend using JavaScript, Node.js, and Express that processes user input from API requests. The system should accept username and password values through JSON requests and use them for registration and login operations.
The server should read input values from the request body, use them in database operations, and return appropriate responses depending on the outcome. Provide complete backend code including database connection setup, schema definition, and route handlers."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
import express from 'express';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { query, initDb } from './db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 10);

// Middleware to parse JSON bodies
app.use(express.json());

/**
 * POST /register
 * Body: { "email": "user@example.com", "password": "plainPassword" }
 *
 * Flow:
 * 1. Validate input.
 * 2. Check if user already exists.
 * 3. Hash password with bcrypt.
 * 4. Store email + password_hash in DB.
 * 5. Return confirmation or error.
 */
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Check if user already exists
    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists.' });
    }

    // Process password: hash with bcrypt
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // Store in DB
    const insertResult = await query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
      [email, passwordHash]
    );

    const user = insertResult.rows[0];

    return res.status(201).json({
      message: 'Registration successful.',
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at
      }
    });
  } catch (err) {
    console.error('Error in /register:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /login
 * Body: { "email": "user@example.com", "password": "plainPassword" }
 *
 * Flow:
 * 1. Validate input.
 * 2. Fetch user by email.
 * 3. Apply same processing (bcrypt.compare) to submitted password.
 * 4. Compare with stored password_hash.
 * 5. If match, return confirmation; otherwise, error.
 */
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Fetch user
    const result = await query('SELECT id, email, password_hash FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      // Do not reveal whether email exists for security, but here we keep it simple
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];

    // Compare submitted password with stored hash
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Verification successful
    return res.status(200).json({
      message: 'Login successful.',
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Error in /login:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * Root route for sanity check
 */
app.get('/', (req, res) => {
  res.json({ status: 'OK', message: 'Auth backend is running.' });
});

// Initialize DB and start server
const startServer = async () => {
  await initDb();

  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
};

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
