 require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const path = require('path');

const { PORT = 3000, PUBLIC_URL, SESSION_SECRET, ENC_KEY } = process.env;
if (!SESSION_SECRET || !ENC_KEY || ENC_KEY.length !== 64) {
  console.error('Set SESSION_SECRET and a 64-hex-char ENC_KEY in .env (see .env.example)');
  process.exit(1);
}
const KEY = Buffer.from(ENC_KEY, 'hex');

// ---- encryption for stored Daraja credentials (AES-256-GCM) ----
const enc = (t) => {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const d = Buffer.concat([c.update(t, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), d]).toString('base64');
};
const dec = (s) => {
  const b = Buffer.from(s, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
};

// ---- database ----
const db = new Database('data.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS channels(
  id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT,
  type TEXT,              -- 'till' or 'paybill'
  receiver TEXT,          -- till number or paybill number (PartyB)
  shortcode TEXT,         -- store/head-office number for tills, paybill for paybills
  env TEXT,               -- 'sandbox' or 'production'
  key_enc TEXT, secret_enc TEXT, passkey_enc TEXT,
  token TEXT,             -- secret part of the callback URL
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY, channel_id INTEGER, phone TEXT, amount INTEGER, reference TEXT,
  checkout_id TEXT UNIQUE, status TEXT DEFAULT 'PENDING', receipt TEXT, message TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

const app = express();
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 864e5 },
}));
app.use(express.static(path.join(__dirname, 'public')));

const auth = (req, res, next) =>
  req.session.uid ? next() : res.status(401).json({ error: 'Please sign in' });
const myChannel = (req) =>
  db.prepare('SELECT * FROM channels WHERE id=? AND user_id=?').get(req.params.id, req.session.uid);

// ---- accounts ----
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 8)
    return res.status(400).json({ error: 'Name, email and a password of 8+ characters are required' });
  try {
    const r = db.prepare('INSERT INTO users(name,email,password) VALUES(?,?,?)')
      .run(name.trim(), email.trim().toLowerCase(), bcrypt.hashSync(password, 10));
    req.session.uid = r.lastInsertRowid;
    res.json({ name });
  } catch { res.status(409).json({ error: 'Email already registered' }); }
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((req.body.email || '').trim().toLowerCase());
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password))
    return res.status(401).json({ error: 'Wrong email or password' });
  req.session.uid = u.id;
  res.json({ name: u.name });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', auth, (req, res) =>
  res.json(db.prepare('SELECT name,email FROM users WHERE id=?').get(req.session.uid)));

// ---- payment channels ----
app.get('/api/channels', auth, (req, res) =>
  res.json(db.prepare('SELECT id,name,type,receiver,shortcode,env,created_at FROM channels WHERE user_id=? ORDER BY id DESC')
    .all(req.session.uid)));

app.post('/api/channels', auth, (req, res) => {
  const { name, type, receiver, shortcode, env, key, secret, passkey } = req.body;
  if (!name || !receiver || !key || !secret || !passkey || !['till', 'paybill'].includes(type) || !['sandbox', 'production'].includes(env))
    return res.status(400).json({ error: 'Please fill in all fields' });
  const sc = type === 'till' ? (shortcode || '').trim() : receiver.trim();
  if (!sc) return res.status(400).json({ error: 'Store number (shortcode) is required for a till' });
  const r = db.prepare(`INSERT INTO channels(user_id,name,type,receiver,shortcode,env,key_enc,secret_enc,passkey_enc,token)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).run(req.session.uid, name.trim(), type, receiver.trim(), sc, env,
    enc(key.trim()), enc(secret.trim()), enc(passkey.trim()), crypto.randomBytes(16).toString('hex'));
  res.json({ id: r.lastInsertRowid });
});

app.delete('/api/channels/:id', auth, (req, res) => {
  const c = myChannel(req);
  if (!c) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM transactions WHERE channel_id=?').run(c.id);
  db.prepare('DELETE FROM channels WHERE id=?').run(c.id);
  res.json({ ok: true });
});

// ---- STK push (uses the channel owner's own credentials, so money goes to their till) ----
const base = (env) => env === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
const normPhone = (p) => {
  p = String(p).replace(/\D/g, '');
  if (/^0[17]\d{8}$/.test(p)) p = '254' + p.slice(1);
  if (/^[17]\d{8}$/.test(p)) p = '254' + p;
  return /^254[17]\d{8}$/.test(p) ? p : null;
};

app.post('/api/channels/:id/pay', auth, async (req, res) => {
  const c = myChannel(req);
  if (!c) return res.status(404).json({ error: 'Not found' });
  const phone = normPhone(req.body.phone);
  const amount = Math.round(Number(req.body.amount));
  if (!phone) return res.status(400).json({ error: 'Enter a valid Safaricom number, e.g. 0712345678' });
  if (!(amount >= 1)) return res.status(400).json({ error: 'Amount must be at least 1' });
  if (!PUBLIC_URL) return res.status(500).json({ error: 'PUBLIC_URL is not set in .env' });

  try {
    const tokenRes = await fetch(`${base(c.env)}/oauth/v1/generate?grant_type=client_credentials`, {
      headers: { Authorization: 'Basic ' + Buffer.from(`${dec(c.key_enc)}:${dec(c.secret_enc)}`).toString('base64') },
    });
    const { access_token } = await tokenRes.json();
    if (!access_token) return res.status(502).json({ error: 'Daraja rejected the channel credentials' });

    const ts = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
    const password = Buffer.from(c.shortcode + dec(c.passkey_enc) + ts).toString('base64');
    const reference = (req.body.reference || c.name).slice(0, 12);
    const r = await fetch(`${base(c.env)}/mpesa/stkpush/v1/processrequest`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        BusinessShortCode: c.shortcode, Password: password, Timestamp: ts,
        TransactionType: c.type === 'till' ? 'CustomerBuyGoodsOnline' : 'CustomerPayBillOnline',
        Amount: amount, PartyA: phone, PartyB: c.receiver, PhoneNumber: phone,
        CallBackURL: `${PUBLIC_URL}/api/callback/${c.token}`,
        AccountReference: reference, TransactionDesc: 'Payment',
      }),
    });
    const d = await r.json();
    if (d.ResponseCode !== '0') return res.status(400).json({ error: d.errorMessage || d.ResponseDescription || 'STK push failed' });
    db.prepare('INSERT INTO transactions(channel_id,phone,amount,reference,checkout_id) VALUES(?,?,?,?,?)')
      .run(c.id, phone, amount, reference, d.CheckoutRequestID);
    res.json({ message: 'Prompt sent. Ask the customer to enter their M-Pesa PIN.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not reach Safaricom' });
  }
});

// ---- Safaricom callback (public; protected by the unguessable token in the URL) ----
app.post('/api/callback/:token', (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  try {
    const ch = db.prepare('SELECT id FROM channels WHERE token=?').get(req.params.token);
    const cb = req.body?.Body?.stkCallback;
    if (!ch || !cb) return;
    let receipt = null;
    for (const i of cb.CallbackMetadata?.Item || []) if (i.Name === 'MpesaReceiptNumber') receipt = i.Value;
    const status = cb.ResultCode === 0 ? 'SUCCESS' : cb.ResultCode === 1032 ? 'CANCELLED' : 'FAILED';
    db.prepare('UPDATE transactions SET status=?, receipt=?, message=? WHERE checkout_id=? AND channel_id=?')
      .run(status, receipt, cb.ResultDesc, cb.CheckoutRequestID, ch.id);
  } catch (e) { console.error(e); }
});

app.get('/api/channels/:id/transactions', auth, (req, res) => {
  const c = myChannel(req);
  if (!c) return res.status(404).json({ error: 'Not found' });
  res.json(db.prepare('SELECT phone,amount,reference,status,receipt,message,created_at FROM transactions WHERE channel_id=? ORDER BY id DESC LIMIT 50').all(c.id));
});

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
