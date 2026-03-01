/*
Dataset Metadata

Scenario: Token management
Prompt Version: Version 1
Model: Chaptgpt-5
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: MySQL
Prompt Used:
"Develop a backend authentication service in Node.js and Express using a relational database. The system should provide registration and login endpoints.
When login succeeds, generate a token and send it to the client. For protected routes, require the client to include the token in the request, and verify it before granting access.
Include all necessary JavaScript code, including database initialization, token handling logic, middleware for verification, and server startup configuration."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// app.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
require('dotenv').config();

// Initialize Express and Database Connection
const app = express();
const port = process.env.PORT || 5000;
app.use(express.json());

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

// Check DB connection
db.connect(err => {
    if (err) {
        console.error('DB connection error: ', err);
        process.exit(1);
    }
    console.log('Database connected');
});

// Register Route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Missing required fields' });
    }

    try {
        // Check if user already exists
        const [existingUser] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user into DB
        const result = await db.promise().query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);
        res.status(201).json({ message: 'User registered successfully', userId: result[0].insertId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Missing required fields' });
    }

    try {
        const [user] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);

        if (user.length === 0) {
            return res.status(400).json({ message: 'User not found' });
        }

        const isPasswordValid = await bcrypt.compare(password, user[0].password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user[0].id, username: user[0].username }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRATION,
        });

        res.json({ message: 'Login successful', token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1]; // Expect token to be sent as "Bearer token"

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user info to request
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

// Protected Route (requires valid JWT)
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

// Start server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});