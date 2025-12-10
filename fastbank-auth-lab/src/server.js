const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;
const SESSION_TTL_MS = 30 * 60 * 1000;

// Disable X-Powered-By
app.disable("x-powered-by");

// Global security headers middleware (MUST BE BEFORE static)
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"
  );

  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=()"
  );

  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Prevent caching (fix Storable & Cacheable Content)
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// Secure user database
const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 12),
  },
];

// Session store with expiration
const sessions = {};

function findUser(username) {
  return users.find((u) => u.username === username);
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function getSession(token) {
  if (!token) return null;
  const s = sessions[token];
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL_MS) {
    delete sessions[token];
    return null;
  }
  return s;
}

// Current user endpoint
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  const session = getSession(token);

  if (!session) {
    return res.status(401).json({ authenticated: false });
  }

  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

// Secure login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  const token = createSessionToken();
  sessions[token] = { userId: user.id, createdAt: Date.now() };

  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: SESSION_TTL_MS,
  });

  res.json({ success: true });
});

// Logout
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
