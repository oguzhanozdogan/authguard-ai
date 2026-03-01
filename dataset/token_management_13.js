/*
Dataset Metadata

Scenario: Token management
Prompt Version: Version 1
Model: Claude Sonnet 4.6
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

// server.js - Application entry point and Express configuration

require("dotenv").config();

const express = require("express");
const { initializeDatabase, statements } = require("./db/database");

// ─── Bootstrap ──────────────────────────────────────────────────────────────

// Initialize DB (creates tables if they don't exist)
initializeDatabase();

// Schedule periodic cleanup of expired/revoked refresh tokens (every 6 hours)
setInterval(() => {
  try {
    const result = statements.cleanExpiredTokens.run();
    if (result.changes > 0) {
      console.log(`🧹  Cleaned ${result.changes} stale refresh tokens`);
    }
  } catch (err) {
    console.error("Token cleanup error:", err);
  }
}, 6 * 60 * 60 * 1000);

// ─── App Setup ──────────────────────────────────────────────────────────────

const app = express();

// Parse JSON bodies
app.use(express.json({ limit: "10kb" }));

// Security headers (basic — use `helmet` for production)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

// Simple rate-limiter (in-memory; use redis-based solution in production)
const requestCounts = new Map();
app.use("/api/auth", (req, res, next) => {
  const ip = req.ip || req.socket.remoteAddress;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxRequests = 20;

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, { count: 1, resetAt: now + windowMs });
    return next();
  }

  const record = requestCounts.get(ip);

  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + windowMs;
    return next();
  }

  record.count++;
  if (record.count > maxRequests) {
    return res.status(429).json({
      success: false,
      error: "Too many requests — please wait before trying again",
      retryAfterSeconds: Math.ceil((record.resetAt - now) / 1000),
    });
  }

  next();
});

// ─── Routes ─────────────────────────────────────────────────────────────────

app.use("/api/auth", require("./routes/auth"));
app.use("/api/users", require("./routes/users"));

// Health check (no auth required)
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: `Route ${req.method} ${req.path} not found` });
});

// Global error handler
app.use((err, req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ success: false, error: "Internal server error" });
});

// ─── Start ───────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3000", 10);

app.listen(PORT, () => {
  console.log(`\n🚀  Auth service running on http://localhost:${PORT}`);
  console.log(`📋  Available endpoints:`);
  console.log(`    POST   /api/auth/register`);
  console.log(`    POST   /api/auth/login`);
  console.log(`    POST   /api/auth/refresh`);
  console.log(`    POST   /api/auth/logout`);
  console.log(`    POST   /api/auth/logout-all  (requires token)`);
  console.log(`    GET    /api/users/me          (requires token)`);
  console.log(`    GET    /api/users/profile     (requires token)`);
  console.log(`    GET    /api/users/admin-dashboard (admin only)`);
  console.log(`    GET    /health\n`);
});

module.exports = app;