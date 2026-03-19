/**
 * HoneyScan VM Manager
 * Manages VirtualBox VM lifecycle using VBoxManage CLI
 * Restores clean snapshot before each scan to prevent cross-contamination
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

const VM_NAME = process.env.VBOX_VM_NAME || 'HoneyScan-Sandbox';
const SNAPSHOT_NAME = process.env.VBOX_SNAPSHOT_NAME || 'CleanState';
const VM_RESTORE_TIMEOUT = 60000; // 60 seconds

/**
 * Restore VM to clean snapshot state
 */
const restoreVM = async (options = {}) => {
  // In development/testing mode, skip VM operations
  if (process.env.SKIP_VM === 'true' || process.env.NODE_ENV === 'development') {
    console.log('[VM] SKIP_VM=true — skipping VirtualBox restore (development mode)');
    return { skipped: true };
  }

  try {
    console.log(`[VM] Powering off VM "${VM_NAME}"...`);
    // Gracefully power off (ignore errors if already off)
    await execAsync(`VBoxManage controlvm "${VM_NAME}" poweroff`).catch(() => {});

    // Wait for VM to fully stop
    await new Promise(r => setTimeout(r, 3000));

    console.log(`[VM] Restoring snapshot "${SNAPSHOT_NAME}"...`);
    const { stdout, stderr } = await execAsync(
      `VBoxManage snapshot "${VM_NAME}" restore "${SNAPSHOT_NAME}"`,
      { timeout: VM_RESTORE_TIMEOUT }
    );

    if (stderr && !stderr.includes('100%')) {
      console.warn('[VM] Restore warning:', stderr);
    }

    // Start VM in headless mode
    console.log(`[VM] Starting VM in headless mode...`);
    await execAsync(`VBoxManage startvm "${VM_NAME}" --type headless`, {
      timeout: VM_RESTORE_TIMEOUT,
    });

    // Wait for VM to boot (SSH ready or fixed delay)
    await waitForVMReady();

    console.log('[VM] VM ready with clean state.');
    return { success: true, vmName: VM_NAME, snapshot: SNAPSHOT_NAME };

  } catch (error) {
    console.error('[VM] Restore failed:', error.message);
    throw new Error(`VM restore failed: ${error.message}`);
  }
};

/**
 * Wait for VM to be ready (check SSH or ping)
 */
const waitForVMReady = async () => {
  const VM_IP = process.env.VBOX_VM_IP || '192.168.56.101';
  const maxAttempts = 30;
  const delay = 2000;

  for (let i = 0; i < maxAttempts; i++) {
    try {
      await execAsync(`ping -c 1 -W 1 ${VM_IP}`, { timeout: 3000 });
      console.log(`[VM] VM responded at ${VM_IP} after ${(i + 1) * delay / 1000}s`);
      return true;
    } catch (_) {
      await new Promise(r => setTimeout(r, delay));
    }
  }

  // If ping fails, use fixed delay as fallback
  console.warn('[VM] VM ping check timed out, using fixed 10s boot delay');
  await new Promise(r => setTimeout(r, 10000));
  return true;
};

/**
 * Get VM status
 */
const getVMStatus = async () => {
  if (process.env.SKIP_VM === 'true') return { state: 'skipped (dev mode)' };

  try {
    const { stdout } = await execAsync(`VBoxManage showvminfo "${VM_NAME}" --machinereadable`);
    const stateMatch = stdout.match(/VMState="(\w+)"/);
    return { state: stateMatch?.[1] || 'unknown', vmName: VM_NAME };
  } catch (error) {
    return { state: 'error', error: error.message };
  }
};

/**
 * List available snapshots
 */
const listSnapshots = async () => {
  if (process.env.SKIP_VM === 'true') return [];

  try {
    const { stdout } = await execAsync(`VBoxManage snapshot "${VM_NAME}" list --machinereadable`);
    const snapshots = [];
    const lines = stdout.split('\n');
    lines.forEach(line => {
      const match = line.match(/SnapshotName(?:-\d+)?="(.+)"/);
      if (match) snapshots.push(match[1]);
    });
    return snapshots;
  } catch (error) {
    console.error('[VM] Could not list snapshots:', error.message);
    return [];
  }
};

module.exports = { restoreVM, getVMStatus, listSnapshots };
