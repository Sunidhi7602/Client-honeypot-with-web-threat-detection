const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/honeyscan', {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log(`[MongoDB] Connected: ${conn.connection.host}`);

    mongoose.connection.on('error', (err) => {
      console.error('[MongoDB] Connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('[MongoDB] Disconnected. Attempting reconnect...');
    });

  } catch (error) {
    console.error('[MongoDB] Initial connection failed:', error.message);
    process.exit(1);
  }
};

module.exports = connectDB;
