const crypto = require('crypto');

// RFC 4648 Base32 alphabet
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encodes a buffer or byte array into a Base32 string.
 * @param {Buffer} buffer 
 * @returns {string}
 */
function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decodes a Base32 string into a Buffer.
 * @param {string} str 
 * @returns {Buffer}
 */
function base32Decode(str) {
  // Clean string: uppercase, remove spaces, hyphens, padding
  const cleaned = str.toUpperCase().replace(/[\s\-=]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: ${cleaned[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generates a random Base32 secret string (default 20 bytes = 160 bits, yields 32 Base32 chars).
 * @param {number} [byteLength=20] 
 * @returns {string}
 */
function generateBase32Secret(byteLength = 20) {
  const bytes = crypto.randomBytes(byteLength);
  return base32Encode(bytes);
}

/**
 * Computes the epoch time step window.
 * @param {number} [timestampMs] - Timestamp in milliseconds (defaults to Date.now())
 * @param {number} [stepSeconds=30] - Time step in seconds
 * @returns {number}
 */
function getTimeWindow(timestampMs = Date.now(), stepSeconds = 30) {
  return Math.floor(Math.floor(timestampMs / 1000) / stepSeconds);
}

/**
 * Generates a 6-digit TOTP code for a given Base32 secret and time window (RFC 6238 / RFC 4226).
 * @param {string} secretBase32 
 * @param {number} timeWindow 
 * @param {number} [digits=6] 
 * @returns {string}
 */
function generateTotpCode(secretBase32, timeWindow, digits = 6) {
  const key = base32Decode(secretBase32);

  // Time window packed as 8-byte big-endian integer
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigInt64BE(BigInt(timeWindow));

  // Compute HMAC-SHA1
  const hmac = crypto.createHmac('sha1', key);
  hmac.update(timeBuffer);
  const digest = hmac.digest();

  // Dynamic truncation
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Verifies a user-provided TOTP code against a secret with clock drift tolerance.
 * Uses constant-time comparison to protect against timing attacks.
 * 
 * @param {string} secretBase32 - The Base32 encoded secret.
 * @param {string} userCode - The 6-digit code provided by user.
 * @param {number} [windowDrift=1] - Windows before and after current to check (default ±1 window = ±30s).
 * @param {number} [timestampMs=Date.now()] - Reference timestamp.
 * @param {number} [stepSeconds=30] - Step size in seconds.
 * @returns {{ valid: boolean, matchWindow: number | null }}
 */
function verifyTotpCode(secretBase32, userCode, windowDrift = 1, timestampMs = Date.now(), stepSeconds = 30) {
  if (!userCode || typeof userCode !== 'string' || userCode.trim().length !== 6) {
    return { valid: false, matchWindow: null };
  }

  const cleanUserCode = userCode.trim();
  const userBuf = Buffer.from(cleanUserCode, 'utf8');
  if (userBuf.length !== 6) {
    return { valid: false, matchWindow: null };
  }

  const currentWindow = getTimeWindow(timestampMs, stepSeconds);

  // Check windows: currentWindow - windowDrift up to currentWindow + windowDrift
  // Ordered by: current window first, then -1, +1, etc.
  const windowsToCheck = [currentWindow];
  for (let offset = 1; offset <= windowDrift; offset++) {
    windowsToCheck.push(currentWindow - offset);
    windowsToCheck.push(currentWindow + offset);
  }

  for (const win of windowsToCheck) {
    try {
      const expected = generateTotpCode(secretBase32, win, 6);
      const expectedBuf = Buffer.from(expected, 'utf8');

      if (expectedBuf.length === userBuf.length && crypto.timingSafeEqual(expectedBuf, userBuf)) {
        return { valid: true, matchWindow: win };
      }
    } catch {
      // Continue checking next window if any calculation fails
    }
  }

  return { valid: false, matchWindow: null };
}

/**
 * Formats standard otpauth:// URI for authenticator apps.
 * @param {string} email 
 * @param {string} secretBase32 
 * @param {string} [issuer='Secure2FAApp'] 
 * @returns {string}
 */
function generateTotpUri(email, secretBase32, issuer = 'Secure2FAApp') {
  const cleanEmail = email.trim();
  const cleanIssuer = issuer.trim();
  const label = encodeURIComponent(`${cleanIssuer}:${cleanEmail}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer: cleanIssuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = {
  base32Encode,
  base32Decode,
  generateBase32Secret,
  getTimeWindow,
  generateTotpCode,
  verifyTotpCode,
  generateTotpUri,
};
