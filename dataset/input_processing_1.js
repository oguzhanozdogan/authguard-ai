/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Chaptgpt-5
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: PostgreSQL
Prompt Used:
"Implement a standalone authentication backend using JavaScript, Node.js, and Express that processes user input from API requests. The system should accept username and password values through JSON requests and use them for registration and login operations.
The server should read input values from the request body, use them in database operations, and return appropriate responses depending on the outcome. Provide complete backend code including database connection setup, schema definition, and route handlers."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
const express = require('express');
const bodyParser = require('body-parser');
const User = require('./models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON
app.use(bodyParser.json());

// JWT Token generation function
const generateToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Register route
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if the email already exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with that email.' });
    }

    // Create a new user with the hashed password
    const user = await User.create({ username, email, password });

    // Generate a JWT token
    const token = generateToken(user);

    return res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error.' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(400).json({ message: 'User not found.' });
    }

    // Compare the password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    // Generate a JWT token
    const token = generateToken(user);

    return res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error.' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});