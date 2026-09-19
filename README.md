# Secure 2FA Login System with TOTP and Encrypted Credential Storage

A robust, production-grade Two-Factor Authentication (2FA) service built in Node.js and PostgreSQL, implementing RFC 6238 Time-Based One-Time Passwords (TOTP), multi-stage challenge state machines, AES-256-GCM symmetric encryption at rest, and atomic transaction-level replay attack protection.

---

## Features & Security Architecture

1. **RFC 6238 TOTP Engine**:
   - Dynamic HMAC-SHA1 calculation with dynamic truncation into 6-digit codes.
   - Clock drift compensation with $\pm 1$ time-step window tolerance ($\pm 30$ seconds).
   - Constant-time comparison (`crypto.timingSafeEqual`) to mitigate timing side-channel attacks.

2. **AES-256-GCM Authenticated Encryption at Rest**:
   - Every Base32 TOTP secret is encrypted before storage in PostgreSQL.
   - A unique 12-byte cryptographically secure random Initialization Vector (IV) is generated for each encryption operation.
   - GCM 16-byte authentication tag guarantees data integrity and tamper detection against chosen-ciphertext modifications.

3. **Multi-Stage Authentication State Machine**:
   - Primary password validation issues a short-lived `2fa_challenge` token (5-minute expiry) when 2FA is active.
   - Challenge tokens are cryptographically isolated from full access tokens and cannot access protected application endpoints.

4. **Replay Attack Defense**:
   - Tracks the exact matched time window integer (`last_totp_window`).
   - Rejects any subsequent code submission where $T_{\text{match}} \le \text{last\_totp\_window}$.
   - Row-level database locking (`SELECT ... FOR UPDATE`) within an ACID transaction prevents concurrent replay race conditions.

5. **Containerized & Orchestrated**:
   - Fully orchestrated with Docker Compose.
   - Automated schema migrations and seeding on startup.
   - Healthchecks on both PostgreSQL and API services.

---

## Database Schema

Table: `users`

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PRIMARY KEY DEFAULT gen_random_uuid()` | Unique user identifier |
| `email` | `VARCHAR(255)` | `UNIQUE, NOT NULL` | User login email |
| `password_hash` | `VARCHAR(255)` | `NOT NULL` | Bcrypt hashed password |
| `totp_enabled` | `BOOLEAN` | `NOT NULL DEFAULT false` | 2FA activation status |
| `totp_secret_encrypted` | `TEXT` | `NULLABLE` | AES-256-GCM encrypted Base32 secret |
| `totp_iv` | `TEXT` | `NULLABLE` | AES-GCM Initialization Vector (Hex) |
| `totp_tag` | `TEXT` | `NULLABLE` | AES-GCM Authentication Tag (Hex) |
| `last_totp_window` | `INTEGER` | `NULLABLE` | Epoch time window of last used TOTP code |

---

## Quickstart & Local Setup

### Prerequisites
- Docker & Docker Compose
- Node.js (v20+) *(for local development/testing)*

### 1. Environment Configuration
Copy the example environment file:
```bash
cp .env.example .env
```

Environment variables:
- `PORT`: Service port (default `3000`)
- `DATABASE_URL`: PostgreSQL connection string (`postgresql://postgres:postgres@db:5432/auth_db` for Docker or `localhost` for local dev)
- `JWT_SECRET`: Signing secret for JWTs
- `MASTER_ENCRYPTION_KEY`: 32-byte (64-character) hex string for AES-256-GCM
- `APP_NAME`: Application issuer name for `otpauth://` URIs

### 2. Start with Docker Compose
```bash
docker compose up -d --build
```
Both services (`db` and `app`) will automatically initialize and become healthy.

### 3. Run Automated Tests
```bash
npm test
```

---

## API Endpoints

### 1. User Registration
`POST /api/auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```
**Response (`201 Created`):**
```json
{
  "id": "c1f7b03a-0e9e-4e6e-bf2d-123456789abc",
  "email": "user@example.com"
}
```

---

### 2. Primary Login
`POST /api/auth/login`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response - 2FA Disabled (`200 OK`):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response - 2FA Enabled (`200 OK`):**
```json
{
  "requires_2fa": true,
  "challenge_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 3. 2FA Provisioning (Setup)
`POST /api/auth/2fa/setup`
**Header:** `Authorization: Bearer <Full Access Token>`

**Response (`200 OK`):**
```json
{
  "secret": "JBSWY3DPEHPK3PXP...",
  "uri": "otpauth://totp/Secure2FAApp%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP...&issuer=Secure2FAApp&algorithm=SHA1&digits=6&period=30"
}
```

---

### 4. 2FA Verification (Activation)
`POST /api/auth/2fa/verify`
**Header:** `Authorization: Bearer <Full Access Token>`

**Request Body:**
```json
{
  "code": "123456"
}
```
**Response (`200 OK`):**
```json
{
  "message": "2FA successfully enabled"
}
```

---

### 5. 2FA Secondary Login
`POST /api/auth/2fa/login`

**Request Body:**
```json
{
  "challenge_token": "<Challenge Token From /api/auth/login>",
  "code": "123456"
}
```
**Response (`200 OK`):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## Test Seeding (`submission.json`)
Pre-configured credentials in `submission.json`:
```json
{
  "testUser": {
    "email": "test_2fa@example.com",
    "password": "securePassword123",
    "plaintextTotpSecret": "JBSWY3DPEHPK3PXP"
  }
}
```
On system initialization, this test user is automatically encrypted and seeded into PostgreSQL with `totp_enabled: true`.
