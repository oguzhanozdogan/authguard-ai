/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1B
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: sqlite3
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

// Database connection configuration
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
  }
});

// Database initialization: Create users table if it doesn't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `, (err) => {
    if (err) {
      console.error('Error creating table:', err.message);
    } else {
      console.log('Users table created or already exists.');
      
      // Insert a sample user if not already present (for demonstration purposes)
      const sampleUsername = 'testuser';
      const samplePassword = 'password123'; // Plain text for hashing
      const hashedPassword = bcrypt.hashSync(samplePassword, 10);
      
      db.run(`
        INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
      `, [sampleUsername, hashedPassword], (err) => {
        if (err) {
          console.error('Error inserting sample user:', err.message);
        } else {
          console.log('Sample user inserted or already exists.');
        }
      });
    }
  });
});

// REST API endpoint for user login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }
  
  // Query the database for the provided username
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('Database query error:', err.message);
      return res.status(500).json({ success: false, message: 'Internal server error.' });
    }
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found.' });
    }
    
    // Compare the submitted password with the stored hashed password
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error('Password comparison error:', err.message);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
      
      if (result) {
        return res.status(200).json({ success: true, message: 'Login successful.' });
      } else {
        return res.status(401).json({ success: false, message: 'Invalid password.' });
      }
    });
  });
});

// Application startup logic
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

// Graceful shutdown to close database connection
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});