const path = require("node:path");
const crypto = require("node:crypto");
const fs = require("node:fs");
const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const rateLimit = require("express-rate-limit");
const sqlite3 = require("sqlite3").verbose();

const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";
const sessionSecret = process.env.SESSION_SECRET;
const databasePath = process.env.DATABASE_PATH || path.join(__dirname, "data", "users.db");

if (isProduction && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error("SESSION_SECRET must be set to at least 32 characters in production.");
}

const app = express();
fs.mkdirSync(path.dirname(databasePath), { recursive: true });
const database = new sqlite3.Database(databasePath);

database.serialize(() => {
  database.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

app.set("view engine", "html");
app.set("views", path.join(__dirname, "views"));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: path.dirname(databasePath) }),
  secret: sessionSecret || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 2
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: "Too many login attempts. Please try again later."
});

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function csrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrfToken;
}

function requireCsrf(req, res, next) {
  const submittedToken = req.body._csrf;
  if (!submittedToken || !req.session.csrfToken ||
      submittedToken.length !== req.session.csrfToken.length ||
      !crypto.timingSafeEqual(Buffer.from(submittedToken), Buffer.from(req.session.csrfToken))) {
    return res.status(403).send("Invalid request token.");
  }
  next();
}

function renderPage(res, title, content, status = 200) {
  res.status(status).send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)} | Secure Login</title>
    <link rel="stylesheet" href="/styles.css">
  </head>
  <body>
    <main class="card">
      <a class="brand" href="/">Secure Login</a>
      ${content}
    </main>
  </body>
</html>`);
}

function formToken(req) {
  return `<input type="hidden" name="_csrf" value="${escapeHtml(csrfToken(req))}">`;
}

function authForm(req, mode, error = "") {
  const isRegister = mode === "register";
  return `
    <h1>${isRegister ? "Create your account" : "Welcome back"}</h1>
    <p class="muted">${isRegister ? "Use a unique email and a strong password." : "Sign in to continue."}</p>
    ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ""}
    <form method="post" action="/${isRegister ? "register" : "login"}">
      ${formToken(req)}
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="email" required maxlength="254">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="${isRegister ? "new-password" : "current-password"}" required minlength="12" maxlength="128">
      ${isRegister ? `<small>At least 12 characters.</small>` : ""}
      <button type="submit">${isRegister ? "Register" : "Log in"}</button>
    </form>
    <p class="switch">${isRegister ? "Already registered?" : "Need an account?"}
      <a href="/${isRegister ? "login" : "register"}">${isRegister ? "Log in" : "Register"}</a>
    </p>`;
}

function findUser(email, callback) {
  database.get("SELECT id, email, password_hash FROM users WHERE email = ?", [email], callback);
}

app.get("/", (req, res) => {
  if (!req.session.userId) return res.redirect("/login");
  renderPage(res, "Dashboard", `
    <h1>You are signed in</h1>
    <p class="muted">Your session is active and protected by an HttpOnly cookie.</p>
    <form method="post" action="/logout">${formToken(req)}<button class="secondary" type="submit">Log out</button></form>`);
});

app.get("/login", (req, res) => renderPage(res, "Log in", authForm(req, "login")));
app.get("/register", (req, res) => renderPage(res, "Register", authForm(req, "register")));

app.post("/register", requireCsrf, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return renderPage(res, "Register", authForm(req, "register", "Enter a valid email address."), 400);
  }
  if (password.length < 12 || password.length > 128) {
    return renderPage(res, "Register", authForm(req, "register", "Password must be 12 to 128 characters."), 400);
  }
  const passwordHash = await bcrypt.hash(password, 12);
  database.run("INSERT INTO users (email, password_hash) VALUES (?, ?)", [email, passwordHash], function (error) {
    if (error?.code === "SQLITE_CONSTRAINT") {
      return renderPage(res, "Register", authForm(req, "register", "An account with that email already exists."), 409);
    }
    if (error) return res.status(500).send("Unable to create account.");
    req.session.regenerate((sessionError) => {
      if (sessionError) return res.status(500).send("Unable to start session.");
      req.session.userId = this.lastID;
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      res.redirect("/");
    });
  });
});

app.post("/login", loginLimiter, requireCsrf, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  findUser(email, async (error, user) => {
    if (error) return res.status(500).send("Unable to sign in.");
    const valid = user && await bcrypt.compare(password, user.password_hash);
    if (!valid) return renderPage(res, "Log in", authForm(req, "login", "Invalid email or password."), 401);
    req.session.regenerate((sessionError) => {
      if (sessionError) return res.status(500).send("Unable to start session.");
      req.session.userId = user.id;
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      res.redirect("/");
    });
  });
});

app.post("/logout", requireCsrf, (req, res) => {
  req.session.destroy((error) => {
    if (error) return res.status(500).send("Unable to log out.");
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`Secure Login running at http://localhost:${PORT}`));
}

module.exports = { app, database };
