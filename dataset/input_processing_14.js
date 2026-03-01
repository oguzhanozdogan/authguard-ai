/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Claude Sonnet 4.6
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a backend authentication service in Node.js using Express and a relational database. The application should expose endpoints for user registration and login that accept credentials from client requests.
The server should process the incoming input data, interact with the database to store or verify user credentials, and return JSON responses indicating success or failure. Provide full JavaScript implementation including server configuration and database initialization so the system runs independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// src/server.js
// Entry point: loads env, wires up graceful shutdown, starts listening.

require('dotenv').config();

const app  = require('./app');
const { db, tokens } = require('./database');

const PORT = parseInt(process.env.PORT || '3000', 10);

// ── Periodic cleanup of expired / revoked refresh tokens ──────────────────────
// Runs every 6 hours so the DB doesn't accumulate stale rows.
const CLEANUP_INTERVAL = 6 * 60 * 60 * 1000;
const cleanupTimer = setInterval(() => {
  try {
    const info = tokens.purgeExpired();
    if (info.changes > 0) {
      console.log(`[DB] Purged ${info.changes} expired/revoked refresh token(s)`);
    }
  } catch (err) {
    console.error('[DB] Cleanup error:', err.message);
  }
}, CLEANUP_INTERVAL);
cleanupTimer.unref(); // don't keep process alive for this alone

// ── Start server ───────────────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log('─────────────────────────────────────────');
  console.log(`  Auth Service  |  http://localhost:${PORT}`);
  console.log(`  Environment   |  ${process.env.NODE_ENV || 'development'}`);
  console.log('─────────────────────────────────────────');
  console.log('  Endpoints:');
  console.log('   POST  /auth/register');
  console.log('   POST  /auth/login');
  console.log('   POST  /auth/refresh');
  console.log('   POST  /auth/logout          (🔒)');
  console.log('   GET   /auth/me              (🔒)');
  console.log('   POST  /auth/change-password (🔒)');
  console.log('   GET   /health');
  console.log('─────────────────────────────────────────');
});

// ── Graceful shutdown ──────────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n[SERVER] ${signal} received — shutting down gracefully…`);
  server.close(() => {
    clearInterval(cleanupTimer);
    db.close();
    console.log('[SERVER] Database closed. Goodbye.');
    process.exit(0);
  });

  // Force-exit after 10 s if connections linger
  setTimeout(() => {
    console.error('[SERVER] Forced exit after timeout.');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException',  err => { console.error('[UNCAUGHT]', err);  shutdown('uncaughtException'); });
process.on('unhandledRejection', err => { console.error('[UNHANDLED]', err); shutdown('unhandledRejection'); });