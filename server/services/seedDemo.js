#!/usr/bin/env node

const { getDemoConnection, seedDemoData } = require('./demoData');
const { importJsonFiles } = require('./importJsonData');

async function run() {
  let connection;

  try {
    connection = await getDemoConnection();
    await seedDemoData({ clearExisting: true, connection });

    const imported = await importJsonFiles({ connection });
    if (imported.insertedCount > 0) {
      console.log(`[Demo Seed] Imported ${imported.insertedCount} scan(s) from server/data JSON files`);
    } else {
      console.log('[Demo Seed] No JSON seed files found in server/data');
    }
  } catch (error) {
    console.error('[Demo Seed] Failed:', error.message);
    process.exitCode = 1;
  } finally {
    if (connection) {
      await connection.close();
      console.log('[Demo Seed] Database connection closed');
    }
  }
}

run();

