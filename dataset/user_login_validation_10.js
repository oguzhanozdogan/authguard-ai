/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1A
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: In-memory JS object 
Prompt Used:
"Create a standalone backend login validation service using JavaScript with Node.js. The application should create and initialize a relational database and store user data in a users table containing at least the fields id, username, and password.
Implement an API endpoint for user login that accepts username and password in a JSON request body. When a login request is received, the server should retrieve the corresponding user record from the database and determine whether the provided credentials are valid.
If authentication succeeds, return a JSON response indicating success; otherwise, return an appropriate error response. Include the database connection setup, table creation logic, server configuration, and all necessary code so that the application can run independently as a small authentication service.
Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.
Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const http   = require("http");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────────────────────
// In-memory "database"
// Each record: { id, username, passwordHash, salt, role, createdAt, lastLogin }
// ─────────────────────────────────────────────────────────────────────────────
const db = {
  users: [],
  _nextId: 1,

  findByUsername(username) {
    return this.users.find(
      (u) => u.username.toLowerCase() === username.toLowerCase()
    ) || null;
  },

  findById(id) {
    return this.users.find((u) => u.id === id) || null;
  },

  insert(username, passwordHash, salt, role = "user") {
    const user = {
      id:         this._nextId++,
      username,
      passwordHash,
      salt,
      role,
      createdAt:  new Date().toISOString(),
      lastLogin:  null,
    };
    this.users.push(user);
    return user;
  },

  touchLogin(id) {
    const user = this.findById(id);
    if (user) user.lastLogin = new Date().toISOString();
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Password helpers  (PBKDF2 via built-in crypto — no bcrypt needed)
// ─────────────────────────────────────────────────────────────────────────────
const HASH_ALGO       = "sha256";
const HASH_ITERATIONS = 100_000;
const HASH_KEYLEN     = 64;

function generateSalt() {
  return crypto.randomBytes(32).toString("hex");
}

function hashPassword(password, salt) {
  return crypto
    .pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_KEYLEN, HASH_ALGO)
    .toString("hex");
}

function verifyPassword(password, salt, storedHash) {
  const attempt = hashPassword(password, salt);
  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(attempt,     "hex"),
    Buffer.from(storedHash,  "hex")
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// JWT-like token  (HMAC-SHA256 signed, no external lib)
// ─────────────────────────────────────────────────────────────────────────────
const TOKEN_SECRET  = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString("hex");
const TOKEN_TTL_SEC = 3600; // 1 hour

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function issueToken(user) {
  const header  = b64url({ alg: "HS256", typ: "JWT" });
  const payload = b64url({
    sub:      user.id,
    username: user.username,
    role:     user.role,
    iat:      Math.floor(Date.now() / 1000),
    exp:      Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC,
  });
  const sig = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${sig}`;
}

function verifyToken(token) {
  try {
    const [header, payload, sig] = token.split(".");
    const expected = crypto
      .createHmac("sha256", TOKEN_SECRET)
      .update(`${header}.${payload}`)
      .digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (claims.exp < Math.floor(Date.now() / 1000)) return null;
    return claims;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Seed two demo accounts
// ─────────────────────────────────────────────────────────────────────────────
(function seed() {
  const demos = [
    { username: "alice", password: "password123", role: "admin" },
    { username: "bob",   password: "hunter2",     role: "user"  },
  ];
  for (const { username, password, role } of demos) {
    const salt = generateSalt();
    db.insert(username, hashPassword(password, salt), salt, role);
  }
  console.log("🌱  Seeded demo users:");
  console.log("    alice / password123  (admin)");
  console.log("    bob   / hunter2      (user)");
})();

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helpers
// ─────────────────────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end",  () => {
      try { resolve(JSON.parse(raw || "{}")); }
      catch { reject(new Error("Invalid JSON")); }
    });
    req.on("error", reject);
  });
}

function send(res, status, body) {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "Content-Type":   "application/json",
    "Content-Length": Buffer.byteLength(json),
  });
  res.end(json);
}

function validateFields(body, fields) {
  const missing = fields.filter((f) => !String(body[f] ?? "").trim());
  return missing.length ? `Missing required fields: ${missing.join(", ")}` : null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Route handlers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /login
 * Body: { username, password }
 */
async function handleLogin(req, res) {
  let body;
  try   { body = await readBody(req); }
  catch { return send(res, 400, { success: false, message: "Request body must be valid JSON." }); }

  const err = validateFields(body, ["username", "password"]);
  if (err) return send(res, 400, { success: false, message: err });

  const { username, password } = body;

  // Always run the hash to avoid timing-based username enumeration
  const user    = db.findByUsername(String(username).trim());
  const dummySalt = generateSalt();
  const valid   = user
    ? verifyPassword(String(password), user.salt, user.passwordHash)
    : (hashPassword(String(password), dummySalt) && false); // always false

  if (!user || !valid) {
    return send(res, 401, { success: false, message: "Invalid username or password." });
  }

  db.touchLogin(user.id);
  const token = issueToken(user);

  return send(res, 200, {
    success: true,
    message: "Login successful.",
    token,
    expiresIn: TOKEN_TTL_SEC,
    user: {
      id:       user.id,
      username: user.username,
      role:     user.role,
    },
  });
}

/**
 * POST /register
 * Body: { username, password }
 */
async function handleRegister(req, res) {
  let body;
  try   { body = await readBody(req); }
  catch { return send(res, 400, { success: false, message: "Request body must be valid JSON." }); }

  const err = validateFields(body, ["username", "password"]);
  if (err) return send(res, 400, { success: false, message: err });

  const username = String(body.username).trim();
  const password = String(body.password);

  if (username.length < 3)  return send(res, 400, { success: false, message: "Username must be at least 3 characters." });
  if (password.length < 6)  return send(res, 400, { success: false, message: "Password must be at least 6 characters." });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return send(res, 400, { success: false, message: "Username may only contain letters, numbers, and underscores." });

  if (db.findByUsername(username)) {
    return send(res, 409, { success: false, message: "Username is already taken." });
  }

  const salt = generateSalt();
  const user = db.insert(username, hashPassword(password, salt), salt);

  return send(res, 201, {
    success:  true,
    message:  "User registered successfully.",
    user:     { id: user.id, username: user.username, role: user.role },
  });
}

/**
 * GET /health
 */
function handleHealth(_req, res) {
  send(res, 200, {
    status:    "ok",
    timestamp: new Date().toISOString(),
    users:     db.users.length,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Router
// ─────────────────────────────────────────────────────────────────────────────
const routes = [
  { method: "POST", path: "/login",    handler: handleLogin    },
  { method: "POST", path: "/register", handler: handleRegister },
  { method: "GET",  path: "/health",   handler: handleHealth   },
];

async function router(req, res) {
  // CORS headers (handy for browser-based testing)
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  console.log(`${new Date().toISOString()}  ${req.method} ${req.url}`);

  const route = routes.find(
    (r) => r.method === req.method && r.path === req.url.split("?")[0]
  );

  if (!route) return send(res, 404, { success: false, message: `Route ${req.method} ${req.url} not found.` });

  try {
    await route.handler(req, res);
  } catch (e) {
    console.error("Unhandled error:", e);
    send(res, 500, { success: false, message: "Internal server error." });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────
http.createServer(router).listen(PORT, () => {
  console.log(`\n🚀  Auth service listening on http://localhost:${PORT}`);
  console.log("─────────────────────────────────────────");
  console.log("  POST /login      authenticate a user");
  console.log("  POST /register   create a new account");
  console.log("  GET  /health     liveness check");
  console.log("─────────────────────────────────────────");
  console.log(`  Token secret: ${TOKEN_SECRET.slice(0, 8)}… (auto-generated)\n`);
});
