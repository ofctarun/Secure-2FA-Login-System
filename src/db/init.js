const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./connection');
const { encrypt } = require('../crypto/encryption');

/**
 * Initializes the database schema and seeds the submission test user.
 * @param {number} [maxRetries=10]
 * @param {number} [retryDelayMs=2000]
 */
async function initializeDatabase(maxRetries = 10, retryDelayMs = 2000) {
  let attempts = 0;

  while (attempts < maxRetries) {
    try {
      attempts++;
      console.log(`[DB] Attempting database initialization (Attempt ${attempts}/${maxRetries})...`);

      // 1. Run Schema
      const schemaSqlPath = path.join(__dirname, 'schema.sql');
      const schemaSql = fs.readFileSync(schemaSqlPath, 'utf8');
      await db.query(schemaSql);
      console.log('[DB] Schema verified and applied successfully.');

      // 2. Seed submission.json test user
      const submissionPath = path.join(__dirname, '../../submission.json');
      if (fs.existsSync(submissionPath)) {
        const submissionData = JSON.parse(fs.readFileSync(submissionPath, 'utf8'));
        if (submissionData && submissionData.testUser) {
          const { email, password, plaintextTotpSecret } = submissionData.testUser;
          
          const passwordHash = await bcrypt.hash(password, 10);
          const encryptedPayload = encrypt(plaintextTotpSecret);

          // Check if test user exists
          const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
          if (existing.rows.length > 0) {
            await db.query(
              `UPDATE users 
               SET password_hash = $1, 
                   totp_enabled = true, 
                   totp_secret_encrypted = $2, 
                   totp_iv = $3, 
                   totp_tag = $4 
               WHERE email = $5`,
              [passwordHash, encryptedPayload.ciphertext, encryptedPayload.iv, encryptedPayload.authTag, email]
            );
            console.log(`[DB] Seeded test user (${email}) updated successfully with 2FA enabled.`);
          } else {
            await db.query(
              `INSERT INTO users (email, password_hash, totp_enabled, totp_secret_encrypted, totp_iv, totp_tag, last_totp_window) 
               VALUES ($1, $2, true, $3, $4, $5, NULL)`,
              [email, passwordHash, encryptedPayload.ciphertext, encryptedPayload.iv, encryptedPayload.authTag]
            );
            console.log(`[DB] Seeded test user (${email}) created successfully with 2FA enabled.`);
          }
        }
      }

      console.log('[DB] Database initialization completed successfully.');
      return;
    } catch (err) {
      console.error(`[DB] Initialization attempt ${attempts} failed:`, err.message);
      if (attempts >= maxRetries) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }
}

if (require.main === module) {
  initializeDatabase()
    .then(() => {
      console.log('[DB] Finished manual init.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[DB] Manual init error:', err);
      process.exit(1);
    });
}

module.exports = {
  initializeDatabase,
};
