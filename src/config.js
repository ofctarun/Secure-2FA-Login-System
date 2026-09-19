const dotenv = require('dotenv');
dotenv.config();

const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  appName: process.env.APP_NAME || 'Secure2FAApp',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/auth_db',
  jwtSecret: process.env.JWT_SECRET || 'default_jwt_secret_key_change_in_production_32bytes_or_more',
  masterEncryptionKeyHex: process.env.MASTER_ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
};

// Validate master key
if (config.masterEncryptionKeyHex) {
  const buf = Buffer.from(config.masterEncryptionKeyHex, 'hex');
  if (buf.length !== 32) {
    throw new Error('MASTER_ENCRYPTION_KEY must be a 32-byte (64 hex characters) string.');
  }
}

module.exports = config;
