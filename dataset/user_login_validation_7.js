/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1B
Model: xAI Grok-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: Sqlite3
Prompt Used:
"Develop a small authentication backend using JavaScript with Node.js. The system should connect to a relational database and expose a REST API endpoint for user login.
The login endpoint should accept user credentials in the request body, query the database for the provided username, compare the submitted password with the stored value, and return a suitable JSON response depending on the authentication result.
Provide complete server-side code, including database initialization, connection configuration, route definitions, and application startup logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;

// Middleware to parse JSON request bodies
app.use(express.json());

// Connect to SQLite database (creates 'users.db' file if it doesn't exist)
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error connecting to database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
  }
});

// Initialize database schema and seed data
function initDatabase() {
  db.serialize(() => {
    // Create users table if it doesn't exist
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )
    `, (err) => {
      if (err) {
        console.error('Error creating table:', err.message);
      }
    });

    // Seed a test user if it doesn't exist (password: 'password123')
    const username = 'testuser';
    const plainPassword = 'password123';
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(plainPassword, salt);

    db.run(`
      INSERT OR IGNORE INTO users (username, password)
      VALUES (?, ?)
    `, [username, hashedPassword], (err) => {
      if (err) {
        console.error('Error seeding test user:', err.message);
      } else {
        console.log('Test user seeded successfully.');
      }
    });
  });
}

// Call initialization
initDatabase();

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Username and password are required.'
    });
  }

  // Query the database for the user
  db.get(`
    SELECT password FROM users WHERE username = ?
  `, [username], (err, row) => {
    if (err) {
      console.error('Database query error:', err.message);
      return res.status(500).json({
        success: false,
        message: 'Internal server error.'
      });
    }

    if (!row) {
      return res.status(401).json({
        success: false,
        message: 'User not found.'
      });
    }

    // Compare provided password with stored hash
    bcrypt.compare(password, row.password, (compareErr, result) => {
      if (compareErr) {
        console.error('Password comparison error:', compareErr.message);
        return res.status(500).json({
          success: false,
          message: 'Internal server error.'
        });
      }

      if (result) {
        return res.status(200).json({
          success: true,
          message: 'Login successful.'
        });
      } else {
        return res.status(401).json({
          success: false,
          message: 'Invalid password.'
        });
      }
    });
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
