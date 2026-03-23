const mongoose = require('mongoose');

const connectDB = async () => {
  const maxRetries = 10;
  let retries = 0;

  const attemptConnection = async () => {
    try {
      const conn = await mongoose.connect(process.env.MONGO_URI || 'mongodb://honeyscan:honeyscan_secret@localhost:27017/honeyscan?authSource=admin', {
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
        retryWrites: true,
        w: 'majority',
      });
      console.log(`[MongoDB] Connected: ${conn.connection.host}`);
      return true;
    } catch (error) {
      retries++;
      console.error(`[MongoDB] Attempt ${retries}/${maxRetries} failed:`, error.message);
      if (retries >= maxRetries) {
        console.error('[MongoDB] All retries exhausted');
        process.exit(1);
      }
      await new Promise(resolve => setTimeout(resolve, 3000 * retries)); // Exponential backoff
      return false;
    }
  };

  mongoose.connection.on('error', (err) => {
    console.error('[MongoDB] Connection error:', err);
  });

  mongoose.connection.on('disconnected', () => {
    console.warn('[MongoDB] Disconnected. Reconnecting...');
  });

  while (retries < maxRetries) {
    if (await attemptConnection()) break;
  }
};

module.exports = connectDB;
