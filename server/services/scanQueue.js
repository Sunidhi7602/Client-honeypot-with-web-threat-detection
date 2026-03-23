const Bull = require('bull');

let scanQueue = null;

const getScanQueue = () => {
  if (scanQueue) return scanQueue;

  const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

  scanQueue = new Bull('scan-jobs', redisUrl, {
    defaultJobOptions: {
      attempts: 2,
      backoff: {
        type: 'exponential',
        delay: 5000,
      },
      removeOnComplete: 100, // Keep last 100 completed
      removeOnFail: 50,
      timeout: 300000, // 5 minutes max per scan
    },
  });

  scanQueue.on('error', (err) => {
    console.error('[Bull] Queue error:', err.message);
  });

  scanQueue.on('waiting', (jobId) => {
    console.log(`[Bull] Job ${jobId} is waiting`);
  });

  scanQueue.on('active', (job) => {
    console.log(`[Bull] Job ${job.id} started processing scan: ${job.data.scanId}`);
  });

  scanQueue.on('completed', (job, result) => {
    console.log(`[Bull] Job ${job.id} completed with score: ${result?.threatScore}`);
  });

  scanQueue.on('failed', (job, err) => {
    console.error(`[Bull] Job ${job.id} failed:`, err.message);
  });

  // Process jobs (concurrency: 2 simultaneous scans)
  scanQueue.process(2, require('./scanProcessor'));

  return scanQueue;
};

const addScanJob = async (jobData) => {
  const queue = getScanQueue();
  const job = await queue.add(jobData, {
    priority: jobData.scanType === 'deep' ? 5 : 10,
  });
  console.log(`[Bull] Enqueued scan job ${job.id} for URL: ${jobData.url}`);
  return job.id;
};

const getQueueStats = async () => {
  const queue = getScanQueue();
  const [waiting, active, completed, failed] = await Promise.all([
    queue.getWaitingCount(),
    queue.getActiveCount(),
    queue.getCompletedCount(),
    queue.getFailedCount(),
  ]);
  return { waiting, active, completed, failed };
};

module.exports = { getScanQueue, addScanJob, getQueueStats };
