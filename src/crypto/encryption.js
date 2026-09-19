const crypto = require('crypto');
const config = require('../config');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 12 bytes standard for GCM

/**
 * Gets the master key buffer from config or parameter.
 * @param {string} [keyHex] 
 * @returns {Buffer}
 */
function getMasterKey(keyHex = config.masterEncryptionKeyHex) {
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) {
    throw new Error('Master key must be exactly 32 bytes.');
  }
  return key;
}

/**
 * Encrypts a plaintext string (like a base32 TOTP secret) using AES-256-GCM.
 * 
 * @param {string} plaintext - The secret to encrypt.
 * @param {string} [keyHex] - Optional override key.
 * @returns {{ iv: string, ciphertext: string, authTag: string }}
 */
function encrypt(plaintext, keyHex) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('Plaintext must be a string');
  }

  const masterKey = getMasterKey(keyHex);
  
  // 1. Generate a random 12-byte IV (Standard for GCM)
  const iv = crypto.randomBytes(IV_LENGTH);
  
  // 2. Create Cipher instance
  const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv);
  
  // 3. Encrypt data
  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  
  // 4. Extract authentication tag (16 bytes)
  const authTag = cipher.getAuthTag().toString('hex');
  
  return {
    iv: iv.toString('hex'),
    ciphertext,
    authTag,
  };
}

/**
 * Decrypts the ciphertext back to the plaintext secret.
 * 
 * @param {string} ivHex - The IV used during encryption.
 * @param {string} ciphertext - The encrypted data (hex).
 * @param {string} authTagHex - The auth tag generated during encryption (hex).
 * @param {string} [keyHex] - Optional override key.
 * @returns {string} The original plaintext secret.
 * @throws Will throw if the auth tag is invalid (tampering detected).
 */
function decrypt(ivHex, ciphertext, authTagHex, keyHex) {
  if (!ivHex || !ciphertext || !authTagHex) {
    throw new Error('Missing required encryption parameters for decryption.');
  }

  const masterKey = getMasterKey(keyHex);
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);
  decipher.setAuthTag(authTag);

  let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');

  return plaintext;
}

module.exports = {
  encrypt,
  decrypt,
  ALGORITHM,
};
