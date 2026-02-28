/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
Prompt Used:
"Create a standalone authentication backend using JavaScript that implements session-based authentication. The application should connect to a relational database containing user records.
After successful login, the server should create a session and associate it with the authenticated user. Implement at least one protected endpoint that can only be accessed if a valid session exists. If a request is made without an active session, access should be denied.
Provide complete backend code including session configuration, middleware for session checking, database connection setup, and server initialization."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║           STANDALONE AUTHENTICATION SERVICE                  ║
 * ║  Node.js · SQLite · Express · Sessions · JWT-ready           ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * SETUP:
 *   npm install express better-sqlite3 express-session bcryptjs uuid
 *   node auth-service.js
 *
 * ENDPOINTS:
 *   POST /api/auth/register   - Register a new user
 *   POST /api/auth/login      - Login and create session
 *   POST /api/auth/logout     - Destroy session
 *   GET  /api/auth/me         - [PROTECTED] Get current user info
 *   GET  /api/protected       - [PROTECTED] Example protected route
 *   GET  /health              - Health check
 */

"use strict";

// ─────────────────────────────────────────────
// DEPENDENCIES
// ─────────────────────────────────────────────
const express      = require("express");
const session      = require("express-session");
const bcrypt       = require("bcryptjs");
const Database     = require("better-sqlite3");
const { v4: uuidv4 } = require("uuid");
const path         = require("path");
const crypto       = require("crypto");

// ─────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────
const CONFIG = {
  port:           process.env.PORT         || 3000,
  dbPath:         process.env.DB_PATH      || path.join(__dirname, "auth.db"),
  sessionSecret:  process.env.SESSION_SECRET || crypto.randomBytes(64).toString("hex"),
  sessionMaxAge:  parseInt(process.env.SESSION_MAX_AGE) || 1000 * 60 * 60 * 24, // 24 hours
  bcryptRounds:   parseInt(process.env.BCRYPT_ROUNDS)   || 12,
  nodeEnv:        process.env.NODE_ENV     || "development",
};

console.log("⚙  Config loaded:", {
  port: CONFIG.port,
  dbPath: CONFIG.dbPath,
  nodeEnv: CONFIG.nodeEnv,
  sessionMaxAge: `${CONFIG.sessionMaxAge / 1000 / 60} minutes`,
});

// ─────────────────────────────────────────────
// DATABASE INITIALIZATION
// ─────────────────────────────────────────────
function initDatabase() {
  const db = new Database(CONFIG.dbPath);

  // Enable WAL mode for better concurrent read performance
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("synchronous = NORMAL");

  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      username     TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      email        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT   NOT NULL,
      role         TEXT    NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin', 'moderator')),
      is_active    INTEGER NOT NULL DEFAULT 1,
      created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      last_login_at TEXT
    );
  `);

  // Sessions table (persistent session store backed by SQLite)
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      sid        TEXT    PRIMARY KEY,
      user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      data       TEXT    NOT NULL DEFAULT '{}',
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      expires_at TEXT    NOT NULL
    );
  `);

  // Audit log table
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    TEXT    REFERENCES users(id) ON DELETE SET NULL,
      action     TEXT    NOT NULL,
      detail     TEXT,
      ip_address TEXT,
      created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
  `);

  // Indexes for performance
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_sessions_user  ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_exp   ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_log(user_id);
  `);

  // Prepared statements
  const stmts = {
    createUser:       db.prepare(`
      INSERT INTO users (id, username, email, password_hash)
      VALUES (@id, @username, @email, @password_hash)
    `),
    findByEmail:      db.prepare(`SELECT * FROM users WHERE email = ? AND is_active = 1`),
    findByUsername:   db.prepare(`SELECT * FROM users WHERE username = ? AND is_active = 1`),
    findById:         db.prepare(`SELECT * FROM users WHERE id = ? AND is_active = 1`),
    updateLastLogin:  db.prepare(`
      UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?
    `),
    createSession:    db.prepare(`
      INSERT INTO sessions (sid, user_id, data, ip_address, user_agent, expires_at)
      VALUES (@sid, @user_id, @data, @ip_address, @user_agent, @expires_at)
    `),
    getSession:       db.prepare(`SELECT * FROM sessions WHERE sid = ? AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`),
    deleteSession:    db.prepare(`DELETE FROM sessions WHERE sid = ?`),
    cleanExpired:     db.prepare(`DELETE FROM sessions WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`),
    logAudit:         db.prepare(`
      INSERT INTO audit_log (user_id, action, detail, ip_address)
      VALUES (@user_id, @action, @detail, @ip_address)
    `),
    listUserSessions: db.prepare(`SELECT sid, ip_address, user_agent, created_at, expires_at FROM sessions WHERE user_id = ?`),
    countUsers:       db.prepare(`SELECT COUNT(*) as count FROM users`),
    countActiveSess:  db.prepare(`SELECT COUNT(*) as count FROM sessions WHERE expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`),
  };

  console.log("🗄  Database initialized:", CONFIG.dbPath);

  return { db, stmts };
}

// ─────────────────────────────────────────────
// CUSTOM SESSION STORE (SQLite-backed)
// ─────────────────────────────────────────────
function createSQLiteSessionStore(stmts, SessionStore) {
  class SQLiteStore extends SessionStore {
    constructor(options = {}) {
      super(options);
      // Clean expired sessions every 15 minutes
      setInterval(() => {
        const result = stmts.cleanExpired.run();
        if (result.changes > 0) {
          console.log(`🧹 Cleaned ${result.changes} expired session(s)`);
        }
      }, 15 * 60 * 1000).unref();
    }

    get(sid, callback) {
      try {
        const row = stmts.getSession.get(sid);
        if (!row) return callback(null, null);
        callback(null, JSON.parse(row.data));
      } catch (err) {
        callback(err);
      }
    }

    set(sid, sessionData, callback) {
      try {
        const expiresAt = new Date(
          Date.now() + (sessionData.cookie?.maxAge || CONFIG.sessionMaxAge)
        ).toISOString();

        const existing = stmts.getSession.get(sid);
        if (existing) {
          // Update existing session data
          const update = stmts.db
            ? stmts.db.prepare(`UPDATE sessions SET data = ?, expires_at = ? WHERE sid = ?`)
            : null;
          if (update) update.run(JSON.stringify(sessionData), expiresAt, sid);
        } else {
          stmts.createSession.run({
            sid,
            user_id:    sessionData.userId || "unknown",
            data:       JSON.stringify(sessionData),
            ip_address: sessionData.ipAddress || null,
            user_agent: sessionData.userAgent || null,
            expires_at: expiresAt,
          });
        }
        callback(null);
      } catch (err) {
        // If user_id FK fails (session set before user saved), silently ignore
        callback(null);
      }
    }

    destroy(sid, callback) {
      try {
        stmts.deleteSession.run(sid);
        callback(null);
      } catch (err) {
        callback(err);
      }
    }

    touch(sid, sessionData, callback) {
      this.set(sid, sessionData, callback);
    }
  }

  return SQLiteStore;
}

// ─────────────────────────────────────────────
// VALIDATION HELPERS
// ─────────────────────────────────────────────
const validators = {
  email(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value).trim());
  },
  username(value) {
    return /^[a-zA-Z0-9_]{3,30}$/.test(String(value).trim());
  },
  password(value) {
    if (typeof value !== "string" || value.length < 8)  return "must be at least 8 characters";
    if (!/[A-Z]/.test(value))  return "must contain at least one uppercase letter";
    if (!/[a-z]/.test(value))  return "must contain at least one lowercase letter";
    if (!/[0-9]/.test(value))  return "must contain at least one number";
    return null; // valid
  },
};

// ─────────────────────────────────────────────
// MIDDLEWARE FACTORIES
// ─────────────────────────────────────────────
function requireAuth(stmts) {
  return (req, res, next) => {
    if (!req.session?.userId) {
      return res.status(401).json({
        success: false,
        error:   "Unauthorized",
        message: "You must be logged in to access this resource.",
      });
    }

    // Attach fresh user data to request
    const user = stmts.findById.get(req.session.userId);
    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({
        success: false,
        error:   "Unauthorized",
        message: "Session references a user that no longer exists.",
      });
    }

    req.user = sanitizeUser(user);
    next();
  };
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error:   "Forbidden",
        message: `This route requires one of these roles: ${roles.join(", ")}`,
      });
    }
    next();
  };
}

function requestLogger(req, _res, next) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.path} — ${req.ip}`);
  next();
}

function sanitizeUser(user) {
  const { password_hash, ...safe } = user;
  return safe;
}

// ─────────────────────────────────────────────
// ROUTE HANDLERS
// ─────────────────────────────────────────────
function buildRouter(stmts) {
  const router = express.Router();

  // ── POST /register ──────────────────────────
  router.post("/register", async (req, res) => {
    const { username, email, password } = req.body || {};

    // Input validation
    const errors = {};
    if (!username || !validators.username(username)) {
      errors.username = "Username must be 3–30 chars, letters/numbers/underscores only";
    }
    if (!email || !validators.email(email)) {
      errors.email = "Must be a valid email address";
    }
    const pwError = validators.password(password);
    if (pwError) {
      errors.password = `Password ${pwError}`;
    }

    if (Object.keys(errors).length > 0) {
      return res.status(422).json({ success: false, error: "Validation failed", errors });
    }

    // Uniqueness check
    const existingEmail    = stmts.findByEmail.get(email.trim().toLowerCase());
    const existingUsername = stmts.findByUsername.get(username.trim());

    if (existingEmail || existingUsername) {
      return res.status(409).json({
        success: false,
        error:   "Conflict",
        errors: {
          ...(existingEmail    ? { email:    "Email is already registered" }    : {}),
          ...(existingUsername ? { username: "Username is already taken" } : {}),
        },
      });
    }

    // Hash password & create user
    const passwordHash = await bcrypt.hash(password, CONFIG.bcryptRounds);
    const userId       = uuidv4();

    stmts.createUser.run({
      id:            userId,
      username:      username.trim(),
      email:         email.trim().toLowerCase(),
      password_hash: passwordHash,
    });

    stmts.logAudit.run({
      user_id:    userId,
      action:     "REGISTER",
      detail:     `New user registered: ${username}`,
      ip_address: req.ip,
    });

    const user = stmts.findById.get(userId);
    console.log(`✅ Registered: ${username} (${userId})`);

    res.status(201).json({
      success: true,
      message: "Account created successfully",
      user:    sanitizeUser(user),
    });
  });

  // ── POST /login ──────────────────────────────
  router.post("/login", async (req, res) => {
    const { identifier, password } = req.body || {};

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        error:   "Bad Request",
        message: "identifier (email or username) and password are required",
      });
    }

    // Find user by email or username
    const isEmail = validators.email(identifier);
    const user    = isEmail
      ? stmts.findByEmail.get(identifier.trim().toLowerCase())
      : stmts.findByUsername.get(identifier.trim());

    if (!user) {
      return res.status(401).json({
        success: false,
        error:   "Invalid credentials",
        message: "No account found with those credentials",
      });
    }

    // Verify password
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      stmts.logAudit.run({
        user_id:    user.id,
        action:     "LOGIN_FAIL",
        detail:     "Wrong password",
        ip_address: req.ip,
      });
      return res.status(401).json({
        success: false,
        error:   "Invalid credentials",
        message: "Password is incorrect",
      });
    }

    // Regenerate session to prevent fixation attacks
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ success: false, error: "Session error" });

      // Store session data
      req.session.userId    = user.id;
      req.session.username  = user.username;
      req.session.role      = user.role;
      req.session.loginAt   = new Date().toISOString();
      req.session.ipAddress = req.ip;
      req.session.userAgent = req.headers["user-agent"] || "";

      stmts.updateLastLogin.run(user.id);
      stmts.logAudit.run({
        user_id:    user.id,
        action:     "LOGIN",
        detail:     "Successful login",
        ip_address: req.ip,
      });

      console.log(`🔓 Login: ${user.username} (session: ${req.session.id})`);

      res.json({
        success:   true,
        message:   "Logged in successfully",
        sessionId: req.session.id,
        user:      sanitizeUser(user),
      });
    });
  });

  // ── POST /logout ─────────────────────────────
  router.post("/logout", (req, res) => {
    const userId   = req.session?.userId;
    const username = req.session?.username;

    req.session.destroy((err) => {
      if (err) return res.status(500).json({ success: false, error: "Could not end session" });

      if (userId) {
        stmts.logAudit.run({
          user_id:    userId,
          action:     "LOGOUT",
          detail:     null,
          ip_address: req.ip,
        });
      }

      res.clearCookie("connect.sid");
      console.log(`🔒 Logout: ${username || "unknown"}`);
      res.json({ success: true, message: "Logged out successfully" });
    });
  });

  // ── GET /me  [PROTECTED] ─────────────────────
  router.get("/me", requireAuth(stmts), (req, res) => {
    res.json({
      success:  true,
      user:     req.user,
      session: {
        id:       req.session.id,
        loginAt:  req.session.loginAt,
        expiresAt: new Date(Date.now() + CONFIG.sessionMaxAge).toISOString(),
      },
    });
  });

  // ── GET /sessions  [PROTECTED] ───────────────
  router.get("/sessions", requireAuth(stmts), (req, res) => {
    const sessions = stmts.listUserSessions.all(req.session.userId);
    res.json({ success: true, sessions });
  });

  return router;
}

// ─────────────────────────────────────────────
// APPLICATION BOOTSTRAP
// ─────────────────────────────────────────────
function createApp() {
  const { db, stmts } = initDatabase();

  // Attach db to stmts so session store can use it for updates
  stmts.db = db;

  const app = express();

  // ── Core middleware ──────────────────────────
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: false, limit: "10kb" }));
  app.use(requestLogger);

  // ── Security headers ─────────────────────────
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    next();
  });

  // ── Session middleware ────────────────────────
  const SQLiteStore    = createSQLiteSessionStore(stmts, session.Store);
  const sessionStore   = new SQLiteStore();

  app.use(session({
    secret:            CONFIG.sessionSecret,
    name:              "authsid",             // custom cookie name
    resave:            false,
    saveUninitialized: false,
    rolling:           true,                  // reset expiry on each request
    store:             sessionStore,
    cookie: {
      httpOnly:  true,
      secure:    CONFIG.nodeEnv === "production",
      sameSite:  "lax",
      maxAge:    CONFIG.sessionMaxAge,
    },
  }));

  // ── Routes ───────────────────────────────────
  app.use("/api/auth", buildRouter(stmts));

  // Example protected route (not under /api/auth)
  app.get("/api/protected", requireAuth(stmts), (req, res) => {
    res.json({
      success: true,
      message: `Welcome to the protected zone, ${req.user.username}!`,
      timestamp: new Date().toISOString(),
    });
  });

  // Admin-only route
  app.get("/api/admin", requireAuth(stmts), requireRole("admin"), (req, res) => {
    const { count: userCount }    = stmts.countUsers.get();
    const { count: sessionCount } = stmts.countActiveSess.get();
    res.json({
      success: true,
      stats: { totalUsers: userCount, activeSessions: sessionCount },
    });
  });

  // Health check
  app.get("/health", (_req, res) => {
    const { count } = stmts.countUsers.get();
    res.json({
      status:    "ok",
      timestamp: new Date().toISOString(),
      db:        "connected",
      users:     count,
    });
  });

  // 404 handler
  app.use((_req, res) => {
    res.status(404).json({ success: false, error: "Not Found" });
  });

  // Global error handler
  app.use((err, _req, res, _next) => {
    console.error("💥 Unhandled error:", err);
    res.status(500).json({
      success: false,
      error:   "Internal Server Error",
      ...(CONFIG.nodeEnv !== "production" ? { detail: err.message } : {}),
    });
  });

  return { app, db };
}

// ─────────────────────────────────────────────
// STARTUP
// ─────────────────────────────────────────────
const { app, db } = createApp();

const server = app.listen(CONFIG.port, () => {
  console.log(`
╔═══════════════════════════════════════════════╗
║        Auth Service is running 🚀             ║
║                                               ║
║  http://localhost:${String(CONFIG.port).padEnd(27)}║
║                                               ║
║  POST  /api/auth/register                     ║
║  POST  /api/auth/login                        ║
║  POST  /api/auth/logout                       ║
║  GET   /api/auth/me          [protected]      ║
║  GET   /api/auth/sessions    [protected]      ║
║  GET   /api/protected        [protected]      ║
║  GET   /api/admin            [admin only]     ║
║  GET   /health                                ║
╚═══════════════════════════════════════════════╝
`);
});

// Graceful shutdown
function shutdown(signal) {
  console.log(`\n📴 ${signal} received — shutting down gracefully...`);
  server.close(() => {
    db.close();
    console.log("👋 Server and database closed. Bye!");
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

module.exports = { app }; // for testing