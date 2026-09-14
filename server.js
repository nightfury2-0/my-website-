require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');

const app = express();
const port = Number(process.env.PORT || 3000);
const dataDir = path.join(__dirname, 'data');
const adminsFile = path.join(dataDir, 'admins.json');
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;

app.use(express.json({ limit: '32kb' }));
app.use(express.static(__dirname, { extensions: ['html'] }));

function ensureAdminStore() {
  fs.mkdirSync(dataDir, { recursive: true });
  if (!fs.existsSync(adminsFile)) {
    const seed = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    const admins = seed ? [{ email: seed, addedAt: new Date().toISOString() }] : [];
    fs.writeFileSync(adminsFile, JSON.stringify(admins, null, 2));
  }
}

function readAdmins() {
  ensureAdminStore();
  try {
    const value = JSON.parse(fs.readFileSync(adminsFile, 'utf8'));
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function writeAdmins(admins) {
  ensureAdminStore();
  const temp = `${adminsFile}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(admins, null, 2));
  fs.renameSync(temp, adminsFile);
}

async function verifyCredential(credential) {
  if (!googleClient || !credential) throw new Error('Google sign-in is not configured.');
  const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: googleClientId });
  const payload = ticket.getPayload();
  if (!payload || !payload.email || !payload.email_verified) throw new Error('Google account email is not verified.');
  return {
    email: payload.email.toLowerCase(),
    name: payload.name || payload.email.split('@')[0],
  };
}

function isAdmin(email) {
  return readAdmins().some((admin) => admin.email === email);
}

async function requireAdmin(req, res) {
  try {
    const user = await verifyCredential(req.body && req.body.credential);
    if (!isAdmin(user.email)) return res.status(403).json({ success: false, error: 'Admin access denied.' });
    req.user = user;
    return true;
  } catch (error) {
    res.status(401).json({ success: false, error: error.message || 'Invalid sign-in.' });
    return false;
  }
}

function getMailer() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: Number(process.env.SMTP_PORT || 465) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

app.get('/config', (_req, res) => {
  res.json({ googleClientId: googleClientId || null });
});

app.post('/auth/google', async (req, res) => {
  try {
    const user = await verifyCredential(req.body && req.body.credential);
    const mailer = getMailer();
    if (!mailer) return res.status(503).json({ success: false, error: 'Email delivery is not configured on the server.' });

    const from = process.env.SMTP_USER;
    const subject = 'Your Daily Dispatch';
    const text = `Hello ${user.name},\n\nYour Daily Dispatch sign-in was successful.\n\nA quote and a page of history can be added here once a content source is configured.\n`;
    await mailer.sendMail({ from, to: user.email, subject, text });

    res.json({ success: true, name: user.name });
  } catch (error) {
    console.error('Google auth/email error:', error.message);
    res.status(401).json({ success: false, error: 'Sign-in or email delivery failed.' });
  }
});

app.post('/api/admins/list', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  res.json({ success: true, you: req.user.email, admins: readAdmins() });
});

app.post('/api/admins/add', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, error: 'Enter a valid email address.' });
  }
  const admins = readAdmins();
  if (!admins.some((admin) => admin.email === email)) {
    admins.push({ email, addedAt: new Date().toISOString() });
    writeAdmins(admins);
  }
  res.json({ success: true, admins: readAdmins() });
});

app.post('/api/admins/remove', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const email = String(req.body.email || '').trim().toLowerCase();
  const admins = readAdmins();
  if (email === req.user.email) return res.status(400).json({ success: false, error: 'You cannot remove your own admin access.' });
  const next = admins.filter((admin) => admin.email !== email);
  if (next.length === admins.length) return res.status(404).json({ success: false, error: 'Admin not found.' });
  writeAdmins(next);
  res.json({ success: true, admins: readAdmins() });
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path === '/config' || req.path === '/auth/google') {
    return res.status(404).json({ success: false, error: 'Not found.' });
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

ensureAdminStore();
app.listen(port, () => console.log(`Daily Dispatch listening on http://localhost:${port}`));
