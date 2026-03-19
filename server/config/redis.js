const IORedis = require('ioredis');

let redisClient = null;

const createRedisClient = () => {
  if (redisClient) return redisClient;

  const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

  redisClient = new IORedis(redisUrl, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    retryStrategy(times) {
      const delay = Math.min(times * 50, 2000);
      console.log(`[Redis] Retrying connection (attempt ${times})...`);
      return delay;
    },
    reconnectOnError(err) {
      const targetError = 'READONLY';
      if (err.message.includes(targetError)) return true;
      return false;
    },
  });

  redisClient.on('connect', () => {
    console.log('[Redis] Connected successfully');
  });

  redisClient.on('error', (err) => {
    console.error('[Redis] Connection error:', err.message);
  });

  redisClient.on('ready', () => {
    console.log('[Redis] Client ready');
  });

  return redisClient;
};

// Bull requires a separate connection per queue
const createBullConnection = () => {
  const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
  return new IORedis(redisUrl, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
  });
};

module.exports = { createRedisClient, createBullConnection };
