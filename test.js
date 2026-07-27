const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());

const db = new Database(':memory:');
db.exec();
db.exec();

function hashPassword(pw) { return crypto.createHash('sha256').update(pw + 'salt').digest('hex'); }
function generateToken() { return crypto.randomBytes(32).toString('hex'); }

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'required' });
  try {
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username.toLowerCase(), hashPassword(password));
    const user = db.prepare('SELECT id, username FROM users WHERE username = ?').get(username.toLowerCase());
    const token = generateToken();
    db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
    res.json({ token, username: user.username });
  } catch(e) { res.status(400).json({ error: 'exists' }); }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username?.toLowerCase());
  if (!user || user.password !== hashPassword(password)) return res.status(401).json({ error: 'invalid' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  const token = generateToken();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
  res.json({ token, username: user.username });
});

app.listen(3503, () => {
  console.log('test on 3503');
  const http = require('http');
  const d = JSON.stringify({username:'test',password:'test123'});
  const r = http.request({hostname:'localhost',port:3503,path:'/api/register',method:'POST',headers:{'Content-Type':'application/json','Content-Length':d.length}}, (res) => {
    let b=''; res.on('data',c=>b+=c); res.on('end',()=>{console.log(res.statusCode, JSON.parse(b)); process.exit(0);});
  });
  r.write(d); r.end();
});
