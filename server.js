require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const AuthUser = require('./models/AuthUser');
const app = express();
app.use(express.json(), helmet());

// Step 1: Password login → issue temp token
app.post('/api/login', async (req, res) => {
  const u = await AuthUser.findOne({ email: req.body.email });
  if (!u || !(await bcrypt.compare(req.body.password, u.passwordHash)))
    return res.status(401).json({ error: 'Invalid creds' });

  if (u.isTotpEnabled) {
    const tmp = jwt.sign({ uid: u._id, stage: 'otp' }, process.env.JWT_SECRET, { expiresIn: '5m' });
    return res.json({ next: 'otp', tmp });
  }
  const token = jwt.sign({ uid: u._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

// Step 2: OTP verify → final JWT
app.post('/api/login/otp', async (req, res) => {
  const { tmp, code } = req.body;
  try {
    const payload = jwt.verify(tmp, process.env.JWT_SECRET);
    if (payload.stage !== 'otp') throw new Error();
    const u = await AuthUser.findById(payload.uid);
    const ok = speakeasy.totp.verify({ secret: u.totpSecret, encoding: 'base32', token: code });
    if (!ok) return res.status(401).json({ error: 'Invalid OTP' });
    const token = jwt.sign({ uid: u._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch { res.status(401).json({ error: 'Expired/invalid tmp' }); }
});

// Enable TOTP (once logged in)
app.post('/api/totp/setup', async (req, res) => {
  const secret = speakeasy.generateSecret({ name: 'BitForge Login' });
  const otpauth = secret.otpauth_url;
  const qr = await QRCode.toDataURL(otpauth);
  res.json({ base32: secret.base32, qr }); // save base32 to user after verification
});

app.listen(3002, () => console.log('Login Vault :3002'));
