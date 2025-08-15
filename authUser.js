const mongoose = require('mongoose');
module.exports = mongoose.model('AuthUser', new mongoose.Schema({
  email: { type: String, unique: true },
  passwordHash: String,
  totpSecret: String, // base32
  isTotpEnabled: { type: Boolean, default: false }
}));
