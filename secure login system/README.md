# Secure Login System

A small login web app built with Node.js, Express, SQLite, bcrypt password hashing, server-side sessions, CSRF protection, Helmet security headers, parameterized SQL, and login rate limiting.

## Run locally

```powershell
npm install
$env:SESSION_SECRET = "replace-with-a-long-random-secret"
npm start
```

Open <http://localhost:3000>.

The app creates `data/users.db` and `data/sessions.db` automatically. Set `NODE_ENV=production` behind HTTPS so session cookies use the `secure` flag.

## Security behavior

- Passwords are hashed with bcrypt using 12 rounds and are never stored in plaintext.
- User queries use SQLite parameters, preventing SQL injection through email input.
- Registration and login validate email and password lengths.
- Sessions are server-side, regenerated after authentication, and protected with HttpOnly, SameSite cookies.
- State-changing forms use a session-bound CSRF token.
- Login attempts are rate limited.
