const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { authMiddleware } = require('../middleware/auth');

const router = express.Router();

const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET || 'dev_secret_change_me',
    { expiresIn: '7d' }
  );
};

// POST /api/auth/register
router.post('/register', [
  body('username').isLength({ min: 3 }).trim(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({
        error: existingUser.email === email ? 'Email already registered' : 'Username taken',
      });
    }

    const user = new User({ username, email, password });
    await user.save();

    const token = generateToken(user._id);
    res.status(201).json({ token, user });
  } catch (error) {
    next(error);
  }
});

// POST /api/auth/login
router.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user._id);
    res.json({ token, user });
  } catch (error) {
    next(error);
  }
});

// GET /api/auth/me
router.get('/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// PUT /api/auth/settings
router.put('/settings', authMiddleware, async (req, res, next) => {
  try {
    const { theme, virusTotalApiKey, scanDefaults, riskWeights, toastPreferences } = req.body;
    const user = await User.findById(req.user._id);

    if (theme) user.settings.theme = theme;
    if (virusTotalApiKey !== undefined) user.settings.virusTotalApiKey = virusTotalApiKey;
    if (scanDefaults) user.settings.scanDefaults = { ...user.settings.scanDefaults, ...scanDefaults };
    if (riskWeights) user.settings.riskWeights = { ...user.settings.riskWeights, ...riskWeights };
    if (toastPreferences) user.settings.toastPreferences = { ...user.settings.toastPreferences, ...toastPreferences };

    await user.save();
    res.json({ user });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
