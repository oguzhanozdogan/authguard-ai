/*
Dataset Metadata

Scenario: Token management
Prompt Version: Version 1
Model: Chaptgpt-5
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: PostgreSQL
Prompt Used:
"Develop a backend authentication service in Node.js and Express using a relational database. The system should provide registration and login endpoints.
When login succeeds, generate a token and send it to the client. For protected routes, require the client to include the token in the request, and verify it before granting access.
Include all necessary JavaScript code, including database initialization, token handling logic, middleware for verification, and server startup configuration."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// Required dependencies
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');

// Initialize the application
const app = express();
app.use(bodyParser.json());

// Environment variables
require('dotenv').config();

// Connect to the database (PostgreSQL example; adjust URI for MySQL)
const sequelize = new Sequelize(process.env.DB_URI, { logging: false });

// Define the User model
const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  }
});

// Hash the password before saving
User.beforeCreate(async (user) => {
  const hashedPassword = await bcrypt.hash(user.password, 10);
  user.password = hashedPassword;
});

// Compare password method
User.prototype.comparePassword = function (password) {
  return bcrypt.compare(password, this.password);
};

// Authenticate JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(403).json({ message: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }
    req.user = user;
    next();
  });
};

// Register route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      return res.status(400).json({ message: 'Username is already taken.' });
    }

    const user = await User.create({ username, password });
    res.status(201).json({ message: 'User created successfully.', user });
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRATION }
    );

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error });
  }
});

// Protected route (Profile)
app.get('/profile', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'Protected profile data', user: req.user });
});

// Sync database and start the server
sequelize.sync().then(() => {
  console.log('Database synced.');
  app.listen(process.env.PORT || 5000, () => {
    console.log(`Server running on port ${process.env.PORT || 5000}`);
  });
}).catch((error) => {
  console.error('Error syncing database:', error);
});