require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const nodemailer = require('nodemailer');

let twilioClient = null;
if (process.env.TWILIO_SID && process.env.TWILIO_AUTH) {
  const twilio = require('twilio');
  twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new SQLiteStore({ 
  db: 'sessions.sqlite', dir: './db' 
}),
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
  maxAge: 1000 * 60 * 60, httpOnly: true 
},
  rolling: true
}));

const fs = require('fs');
const dbDir = path.join(__dirname, 'db');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);

const db = new sqlite3.Database(path.join(dbDir, 'database.sqlite'), 
(err) => {

  if (err) console.error('DB error:', err);
  else console.log('DB verbunden');
});

// Tabellen erstellen
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    identifier TEXT UNIQUE,
    verified INTEGER DEFAULT 0,
    verification_code TEXT,
    password_hash TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY,
    text TEXT,
    done INTEGER DEFAULT 0,
    owner_id INTEGER,
    createdDate TEXT,
    doneDate TEXT,
    FOREIGN KEY(owner_id) REFERENCES users(id)
  )`);
});

// Standardaufgaben
const STANDARD_TASKS = [
  "Hast du deine Zeiterfassung gestartet?",
  "Hast du deine Pause gemacht?",
  "Hast du deine Zeiterfassung beendet?"
];

// Auth & Passwortprüfung
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) 
  return next();
  return res.status(401).json({ 
    error: 'Nicht eingeloggt' 
    });
}
function validatePasswordRules(pw) {
  if (!pw || pw.length < 12) 
    return 'Passwort muss mindestens 12 Zeichen haben.';
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?~]/.test(pw)) 
    return 'Passwort muss mindestens ein Sonderzeichen enthalten.';
    return null;
}

// E-Mail/SMS-Verifikation
async function sendVerificationCode(identifier, code) {
  if (identifier.includes('@') && process.env.SMTP_HOST) {
    try {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587,
        secure: (process.env.SMTP_SECURE === 'true'),
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      });

      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: identifier,
        subject: 'Dein Verifikationscode',
        text: 'Dein Verifikationscode: ' + code
      });

      console.log('E-Mail gesendet an', identifier);
      return;
    } catch (e) { console.error('SMTP Fehler:', e.message); }
  }

  if (!identifier.includes('@') && twilioClient && process.env.TWILIO_FROM) {
    try {
      await twilioClient.messages.create({
        body: 'Dein Verifikationscode: ' + code,
        from: process.env.TWILIO_FROM,
        to: identifier
      });
      console.log('SMS gesendet an', identifier);
      return;
    } catch (e) { console.error('Twilio Fehler:', e.message); }
  }

  console.log('DEV-Verifikationscode für', identifier + ':', code);
}

// Routes
app.post('/api/request-code', (req, res) => {
  const { identifier } = req.body;
  if (!identifier) 
    return res.status(400).json({ 
    error: 'Identifier fehlt' 
  });

  const code = crypto.randomInt(100000, 999999).toString();
  db.get('SELECT id FROM users WHERE identifier = ?', 
    [identifier], 
    (err, row) => {

    if (err) 
      return res.status(500).json({
     error: err.message 
    });

    if (row) {
      db.run('UPDATE users SET verification_code = ?, verified = 0 WHERE id = ?', 
        [code, row.id], 
        e => {

        if(e) 
          return res.status(500).json({ 
          error:e.message 
      });
        sendVerificationCode(identifier, code).catch(() => {});
        return res.json({ 
          status:'ok',
          debugCode: code 
          });
      });

    } else {
      db.run('INSERT INTO users (identifier, verification_code) VALUES (?, ?)',
         [identifier, code], 
         e => {

        if(e) 
          return res.status(500).json({ 
          error:e.message 
        });

        sendVerificationCode(identifier, code).catch(() => {});
        return res.json({ 
          status:'ok', 
          debugCode: code 
        });
      });
    }
  });
});

app.post('/api/verify-and-set', (req,res) => {
  const { identifier, code, password, purpose } 
  = req.body;

  if(!identifier || !code || !password) 
    return res.status(400).json({ 
    error:'Fehlende Daten' 
  });

  const pwErr = validatePasswordRules(password);
  if(pwErr) 
    return res.status(400).json({
    error: pwErr
   });

  db.get('SELECT id, verification_code FROM users WHERE identifier = ?', 
    [identifier], 
    (err,row) => {

    if(err) 
      return res.status(500).json({
      error: err.message 
    });

    if(!row) 
      return res.status(400).json({ 
      error:'Benutzer nicht gefunden' 
    });

    if(row.verification_code !== code.toString()) 
      return res.status(400).json({
      error:'Code falsch' 
    });

    const hash = bcrypt.hashSync(password, 10);
    db.run('UPDATE users SET verified=1, verification_code=NULL, password_hash=? WHERE id=?', 
      [hash,row.id], 
      e => {

      if(e) 
        return res.status(500).json({
        error:e.message 
      });

      // Standardaufgaben nur beim ersten Tag hinzufügen
      if(purpose === 'register') {
        const today = new Date().toISOString().split('T')[0];
        const stmt = db.prepare('INSERT INTO todos (text, done, owner_id, createdDate) VALUES (?,0,?,?)');
        STANDARD_TASKS.forEach(t => stmt.run([t,row.id,today]));
        stmt.finalize();
      }

      req.session.userId = row.id;
      req.session.identifier = identifier;
      return res.json({ 
      status:'ok' 
    });
    });
  });
});

app.post('/api/login', (req,res) => {
  const { identifier, password } = req.body;
  if(!identifier || !password) 
    return res.status(400).json({ 
    error:'Identifier + Passwort benötigt' 
  });

  db.get('SELECT id, verified, password_hash FROM users WHERE identifier=?', 
    [identifier], 
    (err,row) => {

    if(err) 
      return res.status(500).json({ 
      error: err.message 
    });

    if(!row) 
      return res.status(400).json({ 
      error:'Benutzer nicht gefunden' 
    });

    if(!row.verified) 
      return res.status(400).json({ 
      error:'Nicht verifiziert' 
    });

    if(!row.password_hash) 
      return res.status(400).json({ 
      error:'Kein Passwort gesetzt' 
    });

    if(!bcrypt.compareSync(password,row.password_hash)) 
      return res.status(400).json({
      error:'Falsches Passwort'
     });

    req.session.userId = row.id;
    req.session.identifier = identifier;
    return res.json({ 
    status:'ok' 
  });
  });
});

app.post('/api/logout', requireAuth, (req,res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ 
    status:'ok' 
    });
  });
});

// ToDo CRUD
app.get('/api/todos', requireAuth, (req,res) => {
  db.all('SELECT id,text,done,createdDate,doneDate FROM todos WHERE owner_id=?', 
    [req.session.userId], 
    (err,rows) => {

    if(err) 
      return res.status(500).json({ 
    error: err.message 
  });

    res.json(rows);
  });
});

app.post('/api/todos', requireAuth, (req,res) => {
  const { text } = req.body;
  if(!text) 
    return res.status(400).json({
    error:'Text fehlt' 
  });

  const today = new Date().toISOString().split('T')[0];
  db.run('INSERT INTO todos (text, done, owner_id, createdDate) VALUES (?,?,?,?)', 
    [text,0,req.session.userId,today], 
    function(e)
    {

    if(e) 
      return res.status(500).json({ 
    error: e.message 
  });
    res.json({ 
    id:this.lastID, text, done:0 
  });
  });
});

app.post('/api/todos/:id/toggle', requireAuth, (req,res) => {
  const id = req.params.id;
  const now = new Date().toISOString();
  db.get('SELECT done, owner_id FROM todos WHERE id=?',[id],(err,row) => {

    if(err) 
      return res.status(500).json({ 
      error: err.message 
    });

    if(!row) 
      return res.status(404).json({ 
      error:'Nicht gefunden' 
    });

    if(row.owner_id !== req.session.userId) 
      return res.status(403).json({ 
      error:'Nicht berechtigt' 
    });

    const newDone = row.done ? 0 : 1;
    const doneDate = newDone ? now : null;
    db.run('UPDATE todos SET done=?, doneDate=? WHERE id=?',[newDone, doneDate, id], e => {
      if(e) 
        return res.status(500).json({ 
        error:e.message 
      });
      res.json({
      status:'ok', done:newDone 
    });
    });
  });
});

// Aufgabe bearbeiten
app.patch('/api/todos/:id', requireAuth, (req,res) => {
  const { text } = req.body;
  const id = req.params.id;
  if(!text) 
    return res.status(400).json({ 
    error:'Text fehlt' 
  });

  db.get('SELECT owner_id FROM todos WHERE id=?', [id], (err,row) => {
    if(err) 
      return res.status(500).json({
      error: err.message 
  });
    if(!row) 
      return res.status(404).json({
      error:'Nicht gefunden' 
    });

    if(row.owner_id !== req.session.userId) 
      return res.status(403).json({
      error:'Nicht berechtigt' 
    });

    db.run('UPDATE todos SET text=? WHERE id=?', [text,id], e => {
      if(e) 
        return res.status(500).json({
        error:e.message 
      });
      res.json({
      status:'ok', text 
    });
    });
  });
});

// Aufgabe löschen
app.delete('/api/todos/:id', requireAuth, (req,res) => {
  const id = req.params.id;
  db.get('SELECT owner_id FROM todos WHERE id=?',[id],(err,row) => {
    if(err) 
      return res.status(500).json({
      error: err.message 
    });

    if(!row) 
      return res.status(404).json({ 
      error:'Nicht gefunden' 
  });

    if(row.owner_id !== req.session.userId) 
      return res.status(403).json({
      error:'Nicht berechtigt' 
    });

    db.run('DELETE FROM todos WHERE id=?',[id], e => {
      if(e) 
        return res.status(500).json({
        error: e.message 
      });
      res.json({
      status:'ok' 
    });
    });
  });
});

app.listen(PORT,() => console.log('Server läuft auf http://localhost:'+PORT));
