const test = require('node:test');
const assert = require('node:assert');
const { encrypt, decrypt } = require('../src/crypto/encryption');
const {
  base32Encode,
  base32Decode,
  generateBase32Secret,
  getTimeWindow,
  generateTotpCode,
  verifyTotpCode,
  generateTotpUri,
} = require('../src/crypto/totp');

test('Cryptography: AES-256-GCM Encryption and Decryption', async (t) => {
  await t.test('should encrypt and decrypt plaintext accurately', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encrypt(secret);

    assert.ok(encrypted.iv, 'IV must be generated');
    assert.ok(encrypted.ciphertext, 'Ciphertext must be generated');
    assert.ok(encrypted.authTag, 'Auth tag must be generated');

    // Ciphertext must NOT equal or contain plaintext
    assert.notStrictEqual(encrypted.ciphertext, secret);
    assert.strictEqual(encrypted.ciphertext.includes(secret), false);

    // Decryption matches original
    const decrypted = decrypt(encrypted.iv, encrypted.ciphertext, encrypted.authTag);
    assert.strictEqual(decrypted, secret);
  });

  await t.test('should produce unique IV and ciphertext on subsequent encryptions of same secret', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const enc1 = encrypt(secret);
    const enc2 = encrypt(secret);

    assert.notStrictEqual(enc1.iv, enc2.iv, 'IVs must never be reused');
    assert.notStrictEqual(enc1.ciphertext, enc2.ciphertext, 'Ciphertexts must differ due to random IV');
  });

  await t.test('should fail decryption if auth tag is tampered with', () => {
    const secret = 'TOP_SECRET_TOTP';
    const encrypted = encrypt(secret);
    const tamperedTag = '00'.repeat(16);

    assert.throws(
      () => decrypt(encrypted.iv, encrypted.ciphertext, tamperedTag),
      /Unsupported state or unable to authenticate data|tampering/i
    );
  });

  await t.test('should fail decryption if ciphertext is tampered with', () => {
    const secret = 'TOP_SECRET_TOTP';
    const encrypted = encrypt(secret);
    const tamperedCiphertext = 'ff' + encrypted.ciphertext.slice(2);

    assert.throws(
      () => decrypt(encrypted.iv, tamperedCiphertext, encrypted.authTag),
      /Unsupported state or unable to authenticate data/i
    );
  });
});

test('Base32: Encoding and Decoding', async (t) => {
  await t.test('should encode and decode arbitrary buffers', () => {
    const input = Buffer.from('Hello, World 2FA!');
    const encoded = base32Encode(input);
    const decoded = base32Decode(encoded);
    assert.strictEqual(decoded.toString('utf8'), 'Hello, World 2FA!');
  });

  await t.test('should generate valid 20-byte Base32 secret', () => {
    const secret = generateBase32Secret(20);
    assert.strictEqual(typeof secret, 'string');
    assert.strictEqual(secret.length >= 32, true);
    // Ensure all characters are valid Base32 characters
    assert.match(secret, /^[A-Z2-7]+$/);
  });
});

test('TOTP: RFC 6238 Time-Based OTP', async (t) => {
  const testSecret = 'JBSWY3DPEHPK3PXP'; // Base32 for "Hello!\xde\xad\xbe\xef"

  await t.test('should generate 6-digit numeric TOTP codes', () => {
    const window = 59000000;
    const code = generateTotpCode(testSecret, window);
    assert.strictEqual(code.length, 6);
    assert.match(code, /^\d{6}$/);
  });

  await t.test('should verify valid TOTP code in current window', () => {
    const now = Date.now();
    const currentWindow = getTimeWindow(now, 30);
    const code = generateTotpCode(testSecret, currentWindow);

    const result = verifyTotpCode(testSecret, code, 1, now, 30);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.matchWindow, currentWindow);
  });

  await t.test('should verify valid TOTP code with clock drift (T-1)', () => {
    const now = Date.now();
    const currentWindow = getTimeWindow(now, 30);
    const prevWindow = currentWindow - 1;
    const prevCode = generateTotpCode(testSecret, prevWindow);

    const result = verifyTotpCode(testSecret, prevCode, 1, now, 30);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.matchWindow, prevWindow);
  });

  await t.test('should verify valid TOTP code with clock drift (T+1)', () => {
    const now = Date.now();
    const currentWindow = getTimeWindow(now, 30);
    const nextWindow = currentWindow + 1;
    const nextCode = generateTotpCode(testSecret, nextWindow);

    const result = verifyTotpCode(testSecret, nextCode, 1, now, 30);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.matchWindow, nextWindow);
  });

  await t.test('should reject TOTP code outside drift window (T-2 or T+2)', () => {
    const now = Date.now();
    const currentWindow = getTimeWindow(now, 30);
    const farCode = generateTotpCode(testSecret, currentWindow - 2);

    const result = verifyTotpCode(testSecret, farCode, 1, now, 30);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.matchWindow, null);
  });

  await t.test('should reject invalid or malformed codes', () => {
    const now = Date.now();
    assert.strictEqual(verifyTotpCode(testSecret, '000000', 1, now, 30).valid, false);
    assert.strictEqual(verifyTotpCode(testSecret, 'abcdef', 1, now, 30).valid, false);
    assert.strictEqual(verifyTotpCode(testSecret, '', 1, now, 30).valid, false);
    assert.strictEqual(verifyTotpCode(testSecret, null, 1, now, 30).valid, false);
  });

  await t.test('should format otpauth URI properly', () => {
    const uri = generateTotpUri('user@example.com', testSecret, 'TestApp');
    assert.ok(uri.startsWith('otpauth://totp/TestApp%3Auser%40example.com?'));
    assert.ok(uri.includes('secret=JBSWY3DPEHPK3PXP'));
    assert.ok(uri.includes('issuer=TestApp'));
    assert.ok(uri.includes('algorithm=SHA1'));
    assert.ok(uri.includes('digits=6'));
    assert.ok(uri.includes('period=30'));
  });
});
