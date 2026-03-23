const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const rootDir = path.resolve(__dirname, '..');
const clientDir = path.join(rootDir, 'client');
const serverDir = path.join(rootDir, 'server');

const childProcesses = [];
let composeCommand = null;
let shuttingDown = false;
let databasesStartedByScript = false;

function log(message) {
  process.stdout.write(`[start] ${message}\n`);
}

function fileExists(targetPath) {
  return fs.existsSync(targetPath);
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd || rootDir,
      env: options.env || process.env,
      shell: process.platform === 'win32',
      stdio: options.stdio || 'inherit',
    });

    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`));
    });
  });
}

async function ensureDependencies(appDir, name) {
  if (fileExists(path.join(appDir, 'node_modules'))) {
    log(`${name} dependencies already present`);
    return;
  }

  log(`Installing ${name} dependencies`);
  await run('npm', ['install', '--cache', '.npm-cache'], { cwd: appDir });
}

async function detectComposeCommand() {
  const commands = [
    { command: 'docker', args: ['compose', 'version'] },
    { command: 'docker-compose', args: ['version'] },
  ];

  for (const candidate of commands) {
    try {
      await run(candidate.command, candidate.args, { stdio: 'ignore' });
      return candidate.command === 'docker'
        ? { command: 'docker', prefixArgs: ['compose'] }
        : { command: 'docker-compose', prefixArgs: [] };
    } catch (error) {
      // Try the next candidate.
    }
  }

  throw new Error('Docker Compose is required to start MongoDB and Redis. Install Docker Desktop and try again.');
}

function waitForPort(port, host = '127.0.0.1', timeoutMs = 60000) {
  const start = Date.now();

  return new Promise((resolve, reject) => {
    const tryConnect = () => {
      const socket = new net.Socket();

      socket.setTimeout(2000);
      socket.once('connect', () => {
        socket.destroy();
        resolve();
      });
      socket.once('timeout', () => {
        socket.destroy();
        retry();
      });
      socket.once('error', () => {
        socket.destroy();
        retry();
      });

      socket.connect(port, host);
    };

    const retry = () => {
      if (Date.now() - start >= timeoutMs) {
        reject(new Error(`Timed out waiting for ${host}:${port}`));
        return;
      }
      setTimeout(tryConnect, 1000);
    };

    tryConnect();
  });
}

function canConnectToPort(port, host = '127.0.0.1', timeoutMs = 1000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => {
      socket.destroy();
      resolve(false);
    });

    socket.connect(port, host);
  });
}

async function startDatabases() {
  const mongoReady = await canConnectToPort(27017);
  const redisReady = await canConnectToPort(6379);

  if (mongoReady && redisReady) {
    log('Using existing MongoDB and Redis services on localhost');
    return;
  }

  try {
    composeCommand = await detectComposeCommand();
    databasesStartedByScript = true;
    log('Starting MongoDB and Redis with Docker Compose');
    await run(
      composeCommand.command,
      [...composeCommand.prefixArgs, 'up', '-d', 'mongodb', 'redis'],
      { cwd: rootDir }
    );

    log('Waiting for MongoDB on port 27017');
    await waitForPort(27017);
    log('Waiting for Redis on port 6379');
    await waitForPort(6379);
  } catch (error) {
    log(`Docker not available: ${error.message}`);
    if (process.platform === 'win32') {
      log('Install Docker Desktop for Windows:');
      log('  winget install Docker.DockerDesktop');
      log('or');
      log('  choco install docker-desktop');
      log('Then rerun `npm start`.');
    } else {
      log('Install Docker: https://docs.docker.com/get-docker/');
    }
    log('Continuing with dev servers (connect to existing/localhost DBs)...');
  }
}

function spawnLongRunningProcess(name, command, args, options = {}) {
  log(`Starting ${name}`);

    const child = spawn(command, args, {
    cwd: options.cwd || rootDir,
    env: options.env || process.env,
    shell: true,
    windowsHide: true,
    stdio: 'inherit',
  });

  child.on('error', (error) => {
    if (!shuttingDown) {
      process.stderr.write(`[${name}] ${error.message}\n`);
    }
  });

  child.on('exit', (code) => {
    if (!shuttingDown && code !== 0) {
      process.stderr.write(`[${name}] exited with code ${code}\n`);
      shutdown(code || 1).catch((error) => {
        process.stderr.write(`[start] ${error.message}\n`);
        process.exit(code || 1);
      });
    }
  });

  childProcesses.push(child);
}

async function stopDatabases() {
  if (!composeCommand || !databasesStartedByScript) {
    return;
  }

  try {
    await run(
      composeCommand.command,
      [...composeCommand.prefixArgs, 'stop', 'mongodb', 'redis'],
      { cwd: rootDir, stdio: 'ignore' }
    );
  } catch (error) {
    process.stderr.write(`[start] Failed to stop database containers cleanly: ${error.message}\n`);
  }
}

async function shutdown(exitCode = 0) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  log('Shutting down processes');

  for (const child of childProcesses) {
    if (!child.killed) {
      child.kill('SIGINT');
    }
  }

  await wait(1500);
  await stopDatabases();
  process.exit(exitCode);
}

process.on('SIGINT', () => {
  shutdown(0).catch((error) => {
    process.stderr.write(`[start] ${error.message}\n`);
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  shutdown(0).catch((error) => {
    process.stderr.write(`[start] ${error.message}\n`);
    process.exit(1);
  });
});

async function main() {
  await ensureDependencies(serverDir, 'server');
  await ensureDependencies(clientDir, 'client');
  await startDatabases();

  spawnLongRunningProcess('server', 'node', ['index.js'], {
    cwd: serverDir,
    env: {
      ...process.env,
      NODE_ENV: process.env.NODE_ENV || 'development',
      PORT: process.env.PORT || '5000',
      CLIENT_URL: process.env.CLIENT_URL || 'http://localhost:3000',
      JWT_SECRET: process.env.JWT_SECRET || 'dev_honeyscan_secret_change_me',
      MONGO_URI: process.env.MONGO_URI || 'mongodb://honeyscan:honeyscan_secret@localhost:27017/honeyscan?authSource=admin',
      REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
      SKIP_VM: process.env.SKIP_VM || 'true',
      SKIP_WIRESHARK: process.env.SKIP_WIRESHARK || 'true',
      SKIP_SURICATA: process.env.SKIP_SURICATA || 'true',
    },
  });

  await wait(2500);

  spawnLongRunningProcess('client', 'npm', ['run', 'dev'], {
    cwd: clientDir,
    env: {
      ...process.env,
      BROWSER: 'none',
    },
  });

  log('HoneyScan is starting. Frontend: http://localhost:3000  Backend: http://localhost:5000');
}

main().catch(async (error) => {
  process.stderr.write(`[start] ${error.message}\n`);
  await shutdown(1);
});
