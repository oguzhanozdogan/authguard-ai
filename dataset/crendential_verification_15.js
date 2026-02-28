/*
Dataset Metadata

<<<<<<< Updated upstream
Scenario: User Login Validation
Prompt Version: 1A
=======
Scenario: Crendential Verification
Prompt Version: Version 1
>>>>>>> Stashed changes
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
Prompt Used:
Prompt Used:
"Build a complete backend authentication system using JavaScript. The system should manage user accounts stored in a relational database.
When a user registers, their credentials should be stored in the database. When a user attempts to log in, the server should retrieve the corresponding database record and compare the provided credentials to determine whether access should be granted.
Provide all necessary JavaScript code, including database setup, route definitions, and application startup logic, so that the backend runs as a standalone service."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// ─────────────────────────────────────────────
//  server.js  –  Application entry point
// ─────────────────────────────────────────────
"use strict";

// Load .env before anything else
require("dotenv").config();

const express    = require("express");
const rateLimit  = require("express-rate-limit");

const db         = require("./db");
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/users");

const app  = express();
const PORT = parseInt(process.env.PORT) || 3000;

// ── Trust proxy (needed when behind nginx / load balancer) ────────────────────
app.set("trust proxy", 1);

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: false }));

// ── Security headers (lightweight – use helmet in production) ─────────────────
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

// ── Global rate limiter ───────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many requests. Please try again later." },
});
app.use(globalLimiter);

// ── Stricter limiter on auth endpoints ────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: "Too many authentication attempts. Please wait 15 minutes." },
});
app.use("/api/auth/login",    authLimiter);
app.use("/api/auth/register", authLimiter);
app.use("/api/auth/refresh",  authLimiter);

// ── Routes ────────────────────────────────────────────────────────────────────
app.use("/api/auth",  authRoutes);
app.use("/api/users", userRoutes);

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/health", (req, res) =>
  res.json({ status: "ok", timestamp: new Date().toISOString() })
);

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route ${req.method} ${req.path} not found.` });
});

// ── Global error handler ──────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error("[unhandled error]", err);
  res.status(500).json({ success: false, message: "Internal server error." });
});

// ── Start ─────────────────────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║        Auth Backend is running           ║
║                                          ║
║  Server  :  http://localhost:${PORT}        ║
║  DB      :  ${(process.env.DB_PATH || "./data/auth.db").padEnd(26)} ║
║  Env     :  ${(process.env.NODE_ENV || "development").padEnd(26)} ║
╚══════════════════════════════════════════╝
  `);
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n${signal} received – shutting down gracefully…`);
  server.close(() => {
    db.close();
    console.log("Database connection closed. Bye!");
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

module.exports = app; // export for testing