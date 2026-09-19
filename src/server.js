const app = require('./app');
const config = require('./config');
const { initializeDatabase } = require('./db/init');

async function startServer() {
  try {
    console.log('[Server] Initializing database...');
    await initializeDatabase();

    const server = app.listen(config.port, () => {
      console.log(`[Server] Secure 2FA Login System listening on port ${config.port}`);
    });

    // Graceful shutdown
    const shutdown = async () => {
      console.log('\n[Server] Shutting down gracefully...');
      server.close(() => {
        console.log('[Server] HTTP server closed.');
        process.exit(0);
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (err) {
    console.error('[Server] Fatal startup error:', err);
    process.exit(1);
  }
}

startServer();
