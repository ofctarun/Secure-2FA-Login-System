const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db/connection');
const config = require('../config');
const { encrypt, decrypt } = require('../crypto/encryption');
const {
  generateBase32Secret,
  generateTotpCode,
  verifyTotpCode,
  generateTotpUri,
} = require('../crypto/totp');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

/**
 * Validates email format.
 * @param {string} email 
 * @returns {boolean}
 */
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email.trim());
}

/**
 * POST /api/auth/register
 * Register a new user with hashed password.
 */
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: 'A valid email address is required.' });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check if user already exists
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'User with this email already exists.' });
    }

    // Hash password with bcrypt
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert user
    const result = await db.query(
      `INSERT INTO users (email, password_hash, totp_enabled)
       VALUES ($1, $2, false)
       RETURNING id, email`,
      [normalizedEmail, passwordHash]
    );

    const newUser = result.rows[0];
    return res.status(201).json({
      id: newUser.id,
      email: newUser.email,
    });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

/**
 * POST /api/auth/login
 * Primary login endpoint branching on totp_enabled status.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const result = await db.query(
      'SELECT id, email, password_hash, totp_enabled FROM users WHERE email = $1',
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];
    const passwordValid = await bcrypt.compare(password, user.password_hash);

    if (!passwordValid) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Branch based on 2FA status
    if (user.totp_enabled) {
      // Return challenge token (short-lived, 5 min)
      const challengeToken = jwt.sign(
        { userId: user.id, scope: '2fa_challenge' },
        config.jwtSecret,
        { expiresIn: '5m' }
      );

      return res.status(200).json({
        requires_2fa: true,
        challenge_token: challengeToken,
      });
    }

    // 2FA Not Enabled - return full access token
    const token = jwt.sign(
      { userId: user.id, email: user.email, scope: 'access' },
      config.jwtSecret,
      { expiresIn: '1h' }
    );

    return res.status(200).json({
      token,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error during login.' });
  }
});

/**
 * POST /api/auth/2fa/setup
 * Provision TOTP secret and return Base32 secret & OTPAuth URI.
 */
router.post('/2fa/setup', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch user
    const userRes = await db.query('SELECT id, email FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const user = userRes.rows[0];

    // Generate 20-byte random Base32 secret
    const secret = generateBase32Secret(20);

    // Encrypt secret with AES-256-GCM
    const encrypted = encrypt(secret);

    // Store encrypted secret in DB (totp_enabled remains false until verified)
    await db.query(
      `UPDATE users
       SET totp_secret_encrypted = $1,
           totp_iv = $2,
           totp_tag = $3,
           totp_enabled = false
       WHERE id = $4`,
      [encrypted.ciphertext, encrypted.iv, encrypted.authTag, userId]
    );

    // Generate standard otpauth URI
    const uri = generateTotpUri(user.email, secret, config.appName);

    return res.status(200).json({
      secret,
      uri,
    });
  } catch (err) {
    console.error('2FA Setup error:', err);
    return res.status(500).json({ error: 'Internal server error during 2FA setup.' });
  }
});

/**
 * POST /api/auth/2fa/verify
 * Verifies the first TOTP code and activates 2FA for the account.
 */
router.post('/2fa/verify', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { code } = req.body || {};

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'TOTP code is required.' });
    }

    // Retrieve encrypted secret
    const userRes = await db.query(
      'SELECT id, totp_secret_encrypted, totp_iv, totp_tag FROM users WHERE id = $1',
      [userId]
    );

    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = userRes.rows[0];
    if (!user.totp_secret_encrypted || !user.totp_iv || !user.totp_tag) {
      return res.status(400).json({ error: '2FA has not been provisioned. Please call /setup first.' });
    }

    // Decrypt secret
    let secret;
    try {
      secret = decrypt(user.totp_iv, user.totp_secret_encrypted, user.totp_tag);
    } catch (err) {
      console.error('Decryption failed during verify:', err);
      return res.status(500).json({ error: 'Failed to decrypt 2FA credentials.' });
    }

    // Verify TOTP code with ±1 window drift
    const verification = verifyTotpCode(secret, code, 1);
    if (!verification.valid) {
      return res.status(400).json({ error: 'Invalid TOTP code.' });
    }

    // Officially activate 2FA and record the window
    await db.query(
      `UPDATE users
       SET totp_enabled = true,
           last_totp_window = $1
       WHERE id = $2`,
      [verification.matchWindow, userId]
    );

    return res.status(200).json({
      message: '2FA successfully enabled',
    });
  } catch (err) {
    console.error('2FA Verify error:', err);
    return res.status(500).json({ error: 'Internal server error during 2FA verification.' });
  }
});

/**
 * POST /api/auth/2fa/login
 * Validates TOTP code against challenge token with replay protection.
 */
router.post('/2fa/login', async (req, res) => {
  const { challenge_token, code } = req.body || {};

  if (!challenge_token || typeof challenge_token !== 'string') {
    return res.status(400).json({ error: 'challenge_token is required.' });
  }

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: '6-digit code is required.' });
  }

  // 1. Verify Challenge Token
  let decoded;
  try {
    decoded = jwt.verify(challenge_token, config.jwtSecret);
    if (decoded.scope !== '2fa_challenge') {
      return res.status(401).json({ error: 'Invalid token scope. Challenge token required.' });
    }
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired challenge token.' });
  }

  const userId = decoded.userId;

  // 2. Perform verification and replay protection in a database transaction
  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    // Lock user row for update to prevent race conditions / concurrent replay
    const userRes = await client.query(
      `SELECT id, email, totp_enabled, totp_secret_encrypted, totp_iv, totp_tag, last_totp_window 
       FROM users 
       WHERE id = $1 
       FOR UPDATE`,
      [userId]
    );

    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'User not found.' });
    }

    const user = userRes.rows[0];
    if (!user.totp_enabled || !user.totp_secret_encrypted || !user.totp_iv || !user.totp_tag) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: '2FA is not enabled for this user.' });
    }

    // Decrypt secret
    let secret;
    try {
      secret = decrypt(user.totp_iv, user.totp_secret_encrypted, user.totp_tag);
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Decryption failed during 2fa login:', err);
      return res.status(500).json({ error: 'Failed to decrypt 2FA credentials.' });
    }

    // Verify TOTP code with ±1 window drift
    const verification = verifyTotpCode(secret, code, 1);
    if (!verification.valid || verification.matchWindow === null) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Invalid TOTP code.' });
    }

    const matchWindow = verification.matchWindow;

    // Replay Protection Check
    if (user.last_totp_window !== null && user.last_totp_window !== undefined) {
      if (matchWindow <= user.last_totp_window) {
        await client.query('ROLLBACK');
        return res.status(401).json({ error: 'Replay detected: TOTP code has already been used for this time window.' });
      }
    }

    // Update last_totp_window to matchWindow
    await client.query(
      'UPDATE users SET last_totp_window = $1 WHERE id = $2',
      [matchWindow, userId]
    );

    await client.query('COMMIT');

    // Issue Full Access JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, scope: 'access' },
      config.jwtSecret,
      { expiresIn: '1h' }
    );

    return res.status(200).json({
      token,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('2FA Login error:', err);
    return res.status(500).json({ error: 'Internal server error during 2FA login.' });
  } finally {
    client.release();
  }
});

/**
 * GET /api/auth/me
 * Protected route for token verification.
 */
router.get('/me', requireAuth, async (req, res) => {
  try {
    const userRes = await db.query(
      'SELECT id, email, totp_enabled, last_totp_window FROM users WHERE id = $1',
      [req.user.id]
    );
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.status(200).json({ user: userRes.rows[0] });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

module.exports = router;
