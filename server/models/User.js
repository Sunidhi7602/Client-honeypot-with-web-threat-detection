const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true, minlength: 8 },
  role: { type: String, enum: ['analyst', 'admin'], default: 'analyst' },
  settings: {
    theme: { type: String, enum: ['dark', 'light', 'soc'], default: 'dark' },
    virusTotalApiKey: { type: String, default: '' },
    scanDefaults: {
      observationWindow: { type: Number, default: 30 },
      userAgent: { type: String, default: 'HoneyScan/1.0 (Research Scanner)' },
      maxRedirectDepth: { type: Number, default: 5 },
      enableSuricata: { type: Boolean, default: false },
    },
    riskWeights: {
      scriptCount: { type: Number, default: 0.25 },
      redirectCount: { type: Number, default: 0.20 },
      hiddenIframes: { type: Number, default: 0.20 },
      downloadAttempts: { type: Number, default: 0.15 },
      domMutationRate: { type: Number, default: 0.10 },
      externalScripts: { type: Number, default: 0.10 },
    },
    toastPreferences: {
      safe: { type: Boolean, default: false },
      medium: { type: Boolean, default: true },
      high: { type: Boolean, default: true },
      critical: { type: Boolean, default: true },
    },
  },
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now },
});

// Hash password before save
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password
UserSchema.methods.comparePassword = async function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

// Remove password from JSON output
UserSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.settings?.virusTotalApiKey; // Never expose in API response
  return obj;
};

module.exports = mongoose.model('User', UserSchema);
