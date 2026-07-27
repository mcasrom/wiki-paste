const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const db = new Database('data.db');
db.pragma('journal_mode=WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    source_url TEXT DEFAULT '',
    type TEXT NOT NULL DEFAULT 'idea',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS pomodoro (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 0,
    duration INTEGER NOT NULL,
    completed_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'wikipaste-salt').digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getUserFromToken(token) {
  if (!token) return null;
  const session = db.prepare('SELECT user_id FROM sessions WHERE token = ?').get(token);
  if (!session) return null;
  return db.prepare('SELECT id, username FROM users WHERE id = ?').get(session.user_id);
}

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'required' });
  if (password.length < 3) return res.status(400).json({ error: 'password too short' });
  try {
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username.toLowerCase(), hashPassword(password));
    const user = db.prepare('SELECT id, username FROM users WHERE username = ?').get(username.toLowerCase());
    const token = generateToken();
    db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
    res.json({ token, username: user.username });
  } catch (e) {
    res.status(400).json({ error: 'user exists' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username?.toLowerCase());
  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  const token = generateToken();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
  res.json({ token, username: user.username });
});

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = getUserFromToken(token);
  if (!user) return res.status(401).json({ error: 'login required' });
  req.user = user;
  next();
}

app.get('/api/notes', auth, (req, res) => {
  const { q, type } = req.query;
  let rows;
  if (q) {
    rows = db.prepare("SELECT id, title, content, source_url, type, created_at, updated_at FROM notes WHERE user_id = ? AND (title LIKE ? OR content LIKE ?) ORDER BY updated_at DESC").all(req.user.id, '%' + q + '%', '%' + q + '%');
  } else if (type) {
    rows = db.prepare("SELECT id, title, content, source_url, type, created_at, updated_at FROM notes WHERE user_id = ? AND type = ? ORDER BY updated_at DESC").all(req.user.id, type);
  } else {
    rows = db.prepare("SELECT id, title, content, source_url, type, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC").all(req.user.id);
  }
  res.json(rows);
});

app.get('/api/notes/:id', auth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: 'not found' });
  const refs = note.content.match(/\[\[([^\]]+)\]\]/g) || [];
  const links = refs.map(r => {
    const name = r.slice(2, -2).trim();
    const target = db.prepare('SELECT id FROM notes WHERE user_id = ? AND LOWER(title) = LOWER(?)').get(req.user.id, name);
    return { name, id: target ? target.id : null };
  });
  const backlinks = db.prepare('SELECT id, title FROM notes WHERE user_id = ? AND content LIKE ?').all(req.user.id, '%[[' + note.title + ']]%');
  res.json({ note, links, backlinks });
});

app.post('/api/notes', auth, (req, res) => {
  const { title, content, source_url } = req.body;
  const t = (title || '').trim() || (content || '').split('\n')[0].slice(0, 80);
  const result = db.prepare('INSERT INTO notes (user_id, title, content, source_url, type) VALUES (?, ?, ?, ?, ?)').run(req.user.id, t, (content || '').trim(), source_url || '', source_url ? 'paste' : 'idea');
  const note = db.prepare('SELECT id, title, content, source_url, type, created_at, updated_at FROM notes WHERE id = ?').get(result.lastInsertRowid);
  res.json(note);
});

app.put('/api/notes/:id', auth, (req, res) => {
  const { title, content, source_url, type } = req.body;
  const existing = db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  db.prepare("UPDATE notes SET title = ?, content = ?, source_url = ?, type = ?, updated_at = datetime('now') WHERE id = ?").run(
    title ?? existing.title, content ?? existing.content, source_url ?? existing.source_url, type ?? existing.type, req.params.id
  );
  const note = db.prepare('SELECT id, title, content, source_url, type, created_at, updated_at FROM notes WHERE id = ?').get(req.params.id);
  res.json(note);
});

app.delete('/api/notes/:id', auth, (req, res) => {
  db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/pomodoro', auth, (req, res) => {
  const { duration } = req.body;
  db.prepare('INSERT INTO pomodoro (user_id, duration) VALUES (?, ?)').run(req.user.id, duration || 25);
  const stats = db.prepare('SELECT COUNT(*) as sessions, SUM(duration) as total_min FROM pomodoro WHERE user_id = ?').get(req.user.id);
  res.json(stats);
});

app.get('/api/pomodoro/stats', auth, (req, res) => {
  const stats = db.prepare('SELECT COUNT(*) as sessions, SUM(duration) as total_min FROM pomodoro WHERE user_id = ?').get(req.user.id);
  res.json(stats);
});

app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3500;
app.listen(PORT, '0.0.0.0', () => console.log('WikiPaste running on port ' + PORT));
