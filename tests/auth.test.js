const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const db = require('../src/db/connection');
const { initializeDatabase } = require('../src/db/init');
const app = require('../src/app');
const { generateTotpCode, getTimeWindow } = require('../src/crypto/totp');

// Helper to make lightweight HTTP requests against Express app
async function makeRequest(app, method, url, { headers = {}, body = null } = {}) {
  const http = require('http');
  const server = http.createServer(app);

  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  const options = {
    hostname: '127.0.0.1',
    port,
    path: url,
    method: method.toUpperCase(),
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  };

  const responsePromise = new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        let json = null;
        try {
          json = data ? JSON.parse(data) : {};
        } catch {
          json = { raw: data };
        }
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: json,
        });
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });

  try {
    return await responsePromise;
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('Requirement 1 & 2: Project Infrastructure & Environment Documentation', async (t) => {
  await t.test('check docker-compose.yml exists and defines app, db and healthchecks', () => {
    const composePath = path.join(__dirname, '../docker-compose.yml');
    assert.strictEqual(fs.existsSync(composePath), true, 'docker-compose.yml must exist');
    const content = fs.readFileSync(composePath, 'utf8');
    assert.ok(content.includes('db:'), 'docker-compose must define db service');
    assert.ok(content.includes('app:'), 'docker-compose must define app service');
    assert.ok(content.includes('healthcheck:'), 'services must configure healthchecks');
    assert.ok(content.includes('service_healthy'), 'app must wait on db service_healthy condition');
  });

  await t.test('check .env.example exists and contains required variable keys', () => {
    const envExamplePath = path.join(__dirname, '../.env.example');
    assert.strictEqual(fs.existsSync(envExamplePath), true, '.env.example must exist');

    const envContent = fs.readFileSync(envExamplePath, 'utf8');
    const parsed = dotenv.parse(envContent);

    assert.ok('DATABASE_URL' in parsed, 'DATABASE_URL must be defined');
    assert.ok('JWT_SECRET' in parsed, 'JWT_SECRET must be defined');
    assert.ok('MASTER_ENCRYPTION_KEY' in parsed, 'MASTER_ENCRYPTION_KEY must be defined');
    assert.strictEqual(parsed.MASTER_ENCRYPTION_KEY.length, 64, 'MASTER_ENCRYPTION_KEY placeholder must be 64 hex chars (32 bytes)');
  });

  await t.test('check submission.json exists and contains predefined testUser', () => {
    const submissionPath = path.join(__dirname, '../submission.json');
    assert.strictEqual(fs.existsSync(submissionPath), true, 'submission.json must exist');

    const data = JSON.parse(fs.readFileSync(submissionPath, 'utf8'));
    assert.ok(data.testUser, 'testUser must be in submission.json');
    assert.strictEqual(data.testUser.email, 'test_2fa@example.com');
    assert.strictEqual(data.testUser.password, 'securePassword123');
    assert.strictEqual(data.testUser.plaintextTotpSecret, 'JBSWY3DPEHPK3PXP');
  });
});

test('Requirement 3: Database Schema & Users Table', async (t) => {
  await initializeDatabase(5, 1000);

  await t.test('assert users table exists and has all 8 required columns', async () => {
    const res = await db.query(`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'users';
    `);

    const columns = res.rows.map((r) => r.column_name.toLowerCase());
    const requiredCols = [
      'id',
      'email',
      'password_hash',
      'totp_enabled',
      'totp_secret_encrypted',
      'totp_iv',
      'totp_tag',
      'last_totp_window',
    ];

    for (const col of requiredCols) {
      assert.ok(columns.includes(col), `Column ${col} must exist in users table`);
    }
  });
});

test('Requirement 4: User Registration & Password Hashing', async (t) => {
  const uniqueEmail = `reg_user_${Date.now()}@example.com`;
  const plainPassword = 'Password123!';

  await t.test('POST /api/auth/register creates user and returns 201', async () => {
    const res = await makeRequest(app, 'post', '/api/auth/register', {
      body: { email: uniqueEmail, password: plainPassword },
    });

    assert.strictEqual(res.status, 201);
    assert.ok(res.body.id);
    assert.strictEqual(res.body.email, uniqueEmail);

    // Verify DB row
    const userRes = await db.query('SELECT * FROM users WHERE email = $1', [uniqueEmail]);
    assert.strictEqual(userRes.rows.length, 1);
    const user = userRes.rows[0];

    // Password must NOT be plaintext and must be bcrypt hash
    assert.notStrictEqual(user.password_hash, plainPassword);
    assert.ok(user.password_hash.startsWith('$2'));
    assert.strictEqual(user.totp_enabled, false);
  });

  await t.test('rejects duplicate email with 409 Conflict', async () => {
    const res = await makeRequest(app, 'post', '/api/auth/register', {
      body: { email: uniqueEmail, password: plainPassword },
    });
    assert.strictEqual(res.status, 409);
  });

  await t.test('rejects invalid password length (< 8 chars)', async () => {
    const res = await makeRequest(app, 'post', '/api/auth/register', {
      body: { email: `short_${Date.now()}@example.com`, password: 'short' },
    });
    assert.strictEqual(res.status, 400);
  });
});

test('Requirement 5: Primary Login Endpoint Branching', async (t) => {
  const userEmail = `login_test_${Date.now()}@example.com`;
  const password = 'CorrectPassword123!';

  // Create user
  await makeRequest(app, 'post', '/api/auth/register', {
    body: { email: userEmail, password },
  });

  await t.test('returns full access JWT when 2FA is not enabled', async () => {
    const res = await makeRequest(app, 'post', '/api/auth/login', {
      body: { email: userEmail, password },
    });

    assert.strictEqual(res.status, 200);
    assert.ok(res.body.token, 'Should return full access token');
    assert.strictEqual(res.body.requires_2fa, undefined);
  });

  await t.test('returns 401 Unauthorized for incorrect password', async () => {
    const res = await makeRequest(app, 'post', '/api/auth/login', {
      body: { email: userEmail, password: 'WrongPassword' },
    });
    assert.strictEqual(res.status, 401);
  });
});

test('Requirement 6, 7, 8: 2FA Setup, Encryption-At-Rest, & Verification', async (t) => {
  const userEmail = `mfa_user_${Date.now()}@example.com`;
  const password = 'PasswordMfa123!';

  // Register and login to get full access token
  await makeRequest(app, 'post', '/api/auth/register', {
    body: { email: userEmail, password },
  });
  const loginRes = await makeRequest(app, 'post', '/api/auth/login', {
    body: { email: userEmail, password },
  });
  const authToken = loginRes.body.token;

  let provisionedSecret = '';

  await t.test('POST /api/auth/2fa/setup returns Base32 secret and OTPAuth URI', async () => {
    const res = await makeRequest(app, 'post', '/api/auth/2fa/setup', {
      headers: { Authorization: `Bearer ${authToken}` },
    });

    assert.strictEqual(res.status, 200);
    assert.ok(res.body.secret, 'Secret must be returned');
    assert.ok(res.body.uri, 'URI must be returned');
    assert.ok(res.body.uri.startsWith('otpauth://totp/'));
    assert.match(res.body.secret, /^[A-Z2-7]+$/);

    provisionedSecret = res.body.secret;
  });

  await t.test('Encryption at rest: plaintext secret NOT in DB row and IV is unique', async () => {
    const userRes = await db.query('SELECT * FROM users WHERE email = $1', [userEmail]);
    const user = userRes.rows[0];

    assert.ok(user.totp_secret_encrypted);
    assert.ok(user.totp_iv);
    assert.ok(user.totp_tag);
    assert.strictEqual(user.totp_enabled, false, 'totp_enabled must remain false before verify');

    // Secret must NOT be plaintext
    assert.notStrictEqual(user.totp_secret_encrypted, provisionedSecret);
    assert.strictEqual(user.totp_secret_encrypted.includes(provisionedSecret), false);

    // Re-running setup must generate new IV
    const res2 = await makeRequest(app, 'post', '/api/auth/2fa/setup', {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    const userRes2 = await db.query('SELECT * FROM users WHERE email = $1', [userEmail]);
    const user2 = userRes2.rows[0];
    assert.notStrictEqual(user.totp_iv, user2.totp_iv, 'IV must change on every setup');
    provisionedSecret = res2.body.secret; // update for next test
  });

  await t.test('POST /api/auth/2fa/verify activates 2FA with valid TOTP code', async () => {
    const now = Date.now();
    const currentWindow = getTimeWindow(now, 30);
    const validCode = generateTotpCode(provisionedSecret, currentWindow);

    const res = await makeRequest(app, 'post', '/api/auth/2fa/verify', {
      headers: { Authorization: `Bearer ${authToken}` },
      body: { code: validCode },
    });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.message, '2FA successfully enabled');

    // Assert DB state
    const userRes = await db.query('SELECT totp_enabled, last_totp_window FROM users WHERE email = $1', [userEmail]);
    assert.strictEqual(userRes.rows[0].totp_enabled, true);
    assert.strictEqual(userRes.rows[0].last_totp_window, currentWindow);
  });
});

test('Requirement 9, 10, 11: 2FA Login Flow, Token Isolation & Replay Protection', async (t) => {
  const userEmail = `mfa_flow_${Date.now()}@example.com`;
  const password = 'PasswordMfaFlow123!';

  // Register, setup and verify 2FA
  await makeRequest(app, 'post', '/api/auth/register', {
    body: { email: userEmail, password },
  });
  const regLogin = await makeRequest(app, 'post', '/api/auth/login', {
    body: { email: userEmail, password },
  });
  const setupRes = await makeRequest(app, 'post', '/api/auth/2fa/setup', {
    headers: { Authorization: `Bearer ${regLogin.body.token}` },
  });
  const secret = setupRes.body.secret;
  const initialWindow = getTimeWindow(Date.now(), 30);
  const verifyCode = generateTotpCode(secret, initialWindow);
  await makeRequest(app, 'post', '/api/auth/2fa/verify', {
    headers: { Authorization: `Bearer ${regLogin.body.token}` },
    body: { code: verifyCode },
  });

  let challengeToken = '';

  await t.test('POST /api/auth/login returns challenge_token when 2FA is active', async () => {
    const res = await makeRequest(app, 'post', '/api/auth/login', {
      body: { email: userEmail, password },
    });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.requires_2fa, true);
    assert.ok(res.body.challenge_token);
    assert.strictEqual(res.body.token, undefined, 'Must NEVER return full access token on 2FA challenge');

    challengeToken = res.body.challenge_token;
  });

  await t.test('Requirement 10: Challenge token cannot access protected endpoints', async () => {
    const res = await makeRequest(app, 'get', '/api/auth/me', {
      headers: { Authorization: `Bearer ${challengeToken}` },
    });
    assert.strictEqual(res.status, 403, 'Challenge token must be rejected on protected routes');
  });

  await t.test('Requirement 9: POST /api/auth/2fa/login completes authentication with valid code', async () => {
    // Advance window by 1 to ensure new fresh window
    const targetWindow = getTimeWindow(Date.now(), 30) + 1;
    const validCode = generateTotpCode(secret, targetWindow);

    // Reject invalid code
    const badRes = await makeRequest(app, 'post', '/api/auth/2fa/login', {
      body: { challenge_token: challengeToken, code: '000000' },
    });
    assert.strictEqual(badRes.status, 401);

    // Accept valid code
    const goodRes = await makeRequest(app, 'post', '/api/auth/2fa/login', {
      body: { challenge_token: challengeToken, code: validCode },
    });

    assert.strictEqual(goodRes.status, 200);
    assert.ok(goodRes.body.token, 'Must return full access token');

    // Test token accesses protected route
    const meRes = await makeRequest(app, 'get', '/api/auth/me', {
      headers: { Authorization: `Bearer ${goodRes.body.token}` },
    });
    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.body.user.email, userEmail);
  });

  await t.test('Requirement 11: Prevents Replay Attack within same 30s window', async () => {
    // Generate fresh challenge token and valid code for targetWindow
    const loginRes = await makeRequest(app, 'post', '/api/auth/login', {
      body: { email: userEmail, password },
    });
    const freshChallengeToken = loginRes.body.challenge_token;

    // Use current recorded window
    const userRes = await db.query('SELECT last_totp_window FROM users WHERE email = $1', [userEmail]);
    const recordedWindow = userRes.rows[0].last_totp_window;

    // Try to reuse the code from recordedWindow (or send duplicate request)
    const replayedCode = generateTotpCode(secret, recordedWindow);

    const replayRes = await makeRequest(app, 'post', '/api/auth/2fa/login', {
      body: { challenge_token: freshChallengeToken, code: replayedCode },
    });

    assert.strictEqual(replayRes.status, 401, 'Replay attempt must be rejected with 401');
    assert.ok(replayRes.body.error.includes('Replay detected') || replayRes.body.error.includes('already been used'));
  });
});

test('Requirement 12: submission.json Seeded User Evaluation', async () => {
  const submissionPath = path.join(__dirname, '../submission.json');
  const { testUser } = JSON.parse(fs.readFileSync(submissionPath, 'utf8'));

  // Ensure DB has test user seeded
  await initializeDatabase(5, 1000);

  // 1. Step 1: Login with seeded credentials -> returns challenge
  const loginRes = await makeRequest(app, 'post', '/api/auth/login', {
    body: { email: testUser.email, password: testUser.password },
  });

  assert.strictEqual(loginRes.status, 200);
  assert.strictEqual(loginRes.body.requires_2fa, true);
  assert.ok(loginRes.body.challenge_token);

  // 2. Step 2: Dynamically calculate TOTP code from plaintextTotpSecret
  const currentWindow = getTimeWindow(Date.now(), 30);
  const code = generateTotpCode(testUser.plaintextTotpSecret, currentWindow);

  // 3. Step 3: Complete 2FA login
  const mfaLoginRes = await makeRequest(app, 'post', '/api/auth/2fa/login', {
    body: {
      challenge_token: loginRes.body.challenge_token,
      code,
    },
  });

  assert.strictEqual(mfaLoginRes.status, 200);
  assert.ok(mfaLoginRes.body.token);

  // 4. Verify access token works on protected endpoint
  const meRes = await makeRequest(app, 'get', '/api/auth/me', {
    headers: { Authorization: `Bearer ${mfaLoginRes.body.token}` },
  });
  assert.strictEqual(meRes.status, 200);
  assert.strictEqual(meRes.body.user.email, testUser.email);
});
