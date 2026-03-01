/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Copilot GPT4-class
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: Mongodb
Prompt Used:
"Implement a standalone authentication backend using JavaScript, Node.js, and Express that processes user input from API requests. The system should accept username and password values through JSON requests and use them for registration and login operations.
The server should read input values from the request body, use them in database operations, and return appropriate responses depending on the outcome. Provide complete backend code including database connection setup, schema definition, and route handlers."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// ----------------------
// CONFIG
// ----------------------
const app = express();
app.use(cors());
app.use(express.json()); // parse JSON request bodies

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/auth_demo";
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

// ----------------------
// DATABASE CONNECTION
// ----------------------
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err.message);
    process.exit(1);
  });

// ----------------------
// USER SCHEMA
// ----------------------
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    passwordHash: { type: String, required: true }
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ----------------------
// ROUTES
// ----------------------

// REGISTER
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ message: "Username and password required." });

    const existing = await User.findOne({ username });
    if (existing)
      return res.status(409).json({ message: "Username already exists." });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = new User({ username, passwordHash });
    await user.save();

    res.status(201).json({
      message: "User registered.",
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ message: "Username and password required." });

    const user = await User.findOne({ username });
    if (!user)
      return res.status(401).json({ message: "Invalid credentials." });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid)
      return res.status(401).json({ message: "Invalid credentials." });

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful.",
      token,
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// OPTIONAL: Protected route
app.get("/protected", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "Missing Authorization header." });

  const token = auth.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Missing token." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: "Access granted.", user: decoded });
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token." });
  }
});

// ----------------------
// START SERVER
// ----------------------
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
