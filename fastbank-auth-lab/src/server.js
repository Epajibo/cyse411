const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const lusca = require("lusca");

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// Add CSRF protection middleware
app.use(lusca.csrf());

app.use(express.static("public"));
/**
 * USER DB (now with bcrypt)
 * You MUST rehash the initial password with bcrypt.
 */
const users = [
  {
    id: 1,
    username: "student",
    // bcrypt-hashed version of "password123"
    passwordHash: bcrypt.hashSync("password123", 12)
  }
];

// Secure session store
// token -> { userId, expires }
const sessions = {};

/**
 * Helper: find user by username
 */
function findUser(username) {
  return users.find((u) => u.username === username);
}

/**
 * Session creation w/ expiration
 */
function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expires = Date.now() + 30 * 60 * 1000; // 30 min
  
  sessions[token] = Object.assign(Object.create(null), { userId, expires });
  return token;
}

/**
 * Rotate session token
 */
function rotateSession(oldToken, userId) {
  if (oldToken && sessions[oldToken]) {
    delete sessions[oldToken];
  }
  return createSession(userId);
}

/**
 * Authentication middleware
 */
function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ authenticated: false });

  const session = sessions[token];
  if (!session) return res.status(401).json({ authenticated: false });

  // expired?
  if (Date.now() > session.expires) {
    delete sessions[token];
    res.clearCookie("session");
    return res.status(401).json({ authenticated: false });
  }

  // optional sliding expiration
  session.expires = Date.now() + 30 * 60 * 1000;

  req.userId = session.userId;
  next();
}

/**
 * /api/me – now secure and checks expiration
 */
app.get("/api/me", requireAuth, (req, res) => {
  const user = users.find((u) => u.id === req.userId);
  res.json({ authenticated: true, username: user.username });
});

/**
 * SECURE LOGIN ENDPOINT
 * - bcrypt.compare()
 * - generic error
 * - secure random session token
 * - session rotation
 * - secure cookie flags
 * - session expiration
 */
app.post("/api/login", async (req, res) => {
  const INVALID = () =>
    res.status(401).json({ success: false, message: "Invalid username or password" });

  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) return INVALID();

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return INVALID();

  // session rotation (delete old token)
  const oldToken = req.cookies.session;
  const newToken = rotateSession(oldToken, user.id);

  // secure cookie
  res.cookie("session", newToken, {
    httpOnly: true,
    secure: true,        // requires HTTPS
    sameSite: "strict",
    maxAge: 30 * 60 * 1000
  });

  res.json({ success: true });
});

/**
 * Logout
 */
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
