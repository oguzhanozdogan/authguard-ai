/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1B
Model: Chaptgpt-5
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

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
});

pool.on('connect', () => {
    console.log('Connected to PostgreSQL database');
});

pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err);
    process.exit(-1);
});

module.exports = pool;
const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('./db');
require('dotenv').config();

const app = express();
app.use(express.json());

// =========================
// Create Sample User Helper
// =========================
async function createSampleUser() {
    const username = 'admin';
    const plainPassword = 'password123';

    try {
        const hashedPassword = await bcrypt.hash(plainPassword, 10);

        await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING',
            [username, hashedPassword]
        );

        console.log('Sample user ensured');
    } catch (err) {
        console.error('Error creating sample user:', err);
    }
}

// =========================
// LOGIN ENDPOINT
// =========================
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: 'Username and password are required'
        });
    }

    try {
        // Query user from DB
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        const user = result.rows[0];

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Authentication successful
        return res.status(200).json({
            success: true,
            message: 'Authentication successful',
            user: {
                id: user.id,
                username: user.username
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// =========================
// SERVER STARTUP
// =========================
async function startServer() {
    try {
        // Ensure sample user exists
        await createSampleUser();

        app.listen(process.env.PORT, () => {
            console.log(`Server running on port ${process.env.PORT}`);
        });
    } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
}

startServer();