const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const BOT_SECRET = process.env.BOT_SECRET || 'your-secret-here';
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'venom-modz-secret';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(COOKIE_SECRET));

// --- Middlewares ---

const authenticateBot = (req, res, next) => {
  const secret = req.headers['x-bot-secret'];
  if (secret !== BOT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

const checkSession = (req, res, next) => {
  const token = req.signedCookies.session_token;
  
  const handleUnauthorized = (status) => {
    if (req.path === '/Home/Index') {
      return res.redirect(`/Home/Login${status ? '?error=' + status : ''}`);
    }
    return res.status(401).send(status || 'unauthorized');
  };

  if (!token) return handleUnauthorized();

  const session = db.prepare(`
    SELECT s.*, k.status, k.expires_at, k.key_text 
    FROM sessions s 
    JOIN keys k ON s.key_id = k.id 
    WHERE s.session_token = ?
  `).get(token);

  if (!session) return handleUnauthorized();

  // Check if key is revoked
  if (session.status === 'revoked') {
    return handleUnauthorized('revoked');
  }

  // Check if key is expired
  if (session.expires_at && new Date(session.expires_at) < new Date()) {
    db.prepare("UPDATE keys SET status = 'expired' WHERE id = ?").run(session.key_id);
    return handleUnauthorized('expired');
  }

  // Update last active
  db.prepare("UPDATE sessions SET last_active = CURRENT_TIMESTAMP WHERE id = ?").run(session.id);
  
  req.session = session;
  next();
};

// --- Bot Endpoints ---

app.post('/api/keys/register', authenticateBot, (req, res) => {
  const { key, duration_days } = req.body;
  if (!key || !duration_days) {
    return res.status(400).json({ error: 'Missing key or duration' });
  }

  try {
    db.prepare('INSERT INTO keys (key_text, duration_days) VALUES (?, ?)').run(key, duration_days);
    res.status(201).json({ message: 'Key registered successfully' });
  } catch (err) {
    res.status(400).json({ error: 'Key already exists or invalid data' });
  }
});

app.post('/api/keys/revoke', authenticateBot, (req, res) => {
  const { key } = req.body;
  const result = db.prepare("UPDATE keys SET status = 'revoked' WHERE key_text = ?").run(key);
  if (result.changes > 0) {
    res.json({ message: 'Key revoked' });
  } else {
    res.status(404).json({ error: 'Key not found' });
  }
});

app.get('/api/keys/info', authenticateBot, (req, res) => {
  const { key } = req.query;
  const keyInfo = db.prepare('SELECT * FROM keys WHERE key_text = ?').get(key);
  if (keyInfo) {
    res.json(keyInfo);
  } else {
    res.status(404).json({ error: 'Key not found' });
  }
});

// --- Web Endpoints ---

app.get('/Home/Login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/Home/Login', (req, res) => {
  const { key } = req.body;
  
  const keyInfo = db.prepare('SELECT * FROM keys WHERE key_text = ?').get(key);
  
  if (!keyInfo) {
    return res.redirect('/Home/Login?error=invalid');
  }
  
  if (keyInfo.status === 'revoked') {
    return res.redirect('/Home/Login?error=revoked');
  }
  
  // Check expiration if already redeemed
  if (keyInfo.expires_at && new Date(keyInfo.expires_at) < new Date()) {
    db.prepare("UPDATE keys SET status = 'expired' WHERE id = ?").run(keyInfo.id);
    return res.redirect('/Home/Login?error=expired');
  }
  
  // If not redeemed, set expiration now
  if (!keyInfo.expires_at) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + keyInfo.duration_days);
    db.prepare("UPDATE keys SET expires_at = ?, status = 'active' WHERE id = ?").run(expiresAt.toISOString(), keyInfo.id);
  }
  
  // Create session
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (session_token, key_id) VALUES (?, ?)').run(token, keyInfo.id);
  
  res.cookie('session_token', token, { 
    signed: true, 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  });
  
  res.redirect('/Home/Index');
});

app.get('/Home/Index', checkSession, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/Home/CheckSession', (req, res) => {
  const token = req.signedCookies.session_token;
  if (!token) return res.status(401).send('unauthorized');

  const session = db.prepare(`
    SELECT s.*, k.status, k.expires_at 
    FROM sessions s 
    JOIN keys k ON s.key_id = k.id 
    WHERE s.session_token = ?
  `).get(token);

  if (!session) return res.status(401).send('unauthorized');
  if (session.status === 'revoked') return res.status(401).send('revoked');
  if (session.expires_at && new Date(session.expires_at) < new Date()) {
    db.prepare("UPDATE keys SET status = 'expired' WHERE id = ?").run(session.key_id);
    return res.status(401).send('expired');
  }

  res.status(200).send('ok');
});

app.post('/Home/Logout', (req, res) => {
  const token = req.signedCookies.session_token;
  if (token) {
    db.prepare('DELETE FROM sessions WHERE session_token = ?').run(token);
  }
  res.clearCookie('session_token');
  res.redirect('/Home/Login');
});

// Default redirect
app.get('/', (req, res) => {
  res.redirect('/Home/Index');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
