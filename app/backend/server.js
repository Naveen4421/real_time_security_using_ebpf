const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const client = require('prom-client');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Enable collection of default metrics (CPU, Memory usage, etc.)
const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics({ register: client.register });

// Custom counter to track threat triggers (Preserved for compatibility)
const threatCounter = new client.Counter({
  name: 'security_demo_threat_triggers_total',
  help: 'Total number of security threats triggered in the simulator backend',
  labelNames: ['threat_type', 'status']
});

// Custom metrics for RASP and active responses
const raspBlockCounter = new client.Counter({
  name: 'security_demo_rasp_blocks_total',
  help: 'Total number of security events blocked in-app by RASP engine',
  labelNames: ['threat_type', 'rule']
});

const lockdownCounter = new client.Counter({
  name: 'security_demo_lockdowns_total',
  help: 'Total number of active system lockdowns triggered'
});

// In-memory Incident and State Management
let incidents = [];
let systemLockdown = false;
let lockdownExpiry = null;
let consecutiveThreats = 0;

function checkLockdown() {
  if (systemLockdown && lockdownExpiry && Date.now() > lockdownExpiry) {
    systemLockdown = false;
    lockdownExpiry = null;
    consecutiveThreats = 0;
    incidents.unshift({
      id: Date.now().toString() + '-sys',
      timestamp: new Date().toISOString(),
      source: 'RASP Active Response Engine',
      type: 'Containment Lifted',
      message: 'System containment timeout expired. Resuming normal operations.',
      priority: 'INFO',
      fields: {},
      mitigation: 'Access Restored',
      status: 'Resolved'
    });
  }
  return systemLockdown;
}

function triggerLockdown(durationMs = 30000) {
  systemLockdown = true;
  lockdownExpiry = Date.now() + durationMs;
  lockdownCounter.inc();
  
  incidents.unshift({
    id: Date.now().toString() + '-lock',
    timestamp: new Date().toISOString(),
    source: 'RASP Active Response Engine',
    type: 'System Lockdown Activated',
    message: `Active Threat Threshold exceeded! Automatically blocking access to sensitive API endpoints for ${durationMs / 1000} seconds.`,
    priority: 'CRITICAL',
    fields: { duration: `${durationMs / 1000}s`, threat_count: consecutiveThreats },
    mitigation: 'Lockdown Route Restrictions',
    status: 'Active'
  });
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Backend is running',
    lockdown: checkLockdown(),
    lockdownRemaining: lockdownExpiry ? Math.max(0, Math.ceil((lockdownExpiry - Date.now()) / 1000)) : 0
  });
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.end(await client.register.metrics());
});

// GET endpoints for Security Status and Incidents
app.get('/api/security/incidents', (req, res) => {
  checkLockdown();
  res.json(incidents.slice(0, 50)); // Return last 50 incidents
});

app.get('/api/security/status', (req, res) => {
  res.json({
    lockdown: checkLockdown(),
    lockdownRemainingSeconds: lockdownExpiry ? Math.max(0, Math.ceil((lockdownExpiry - Date.now()) / 1000)) : 0,
    threatCount: consecutiveThreats,
    incidentCount: incidents.length
  });
});

// RESET endpoint to clear logs and lift lockdown
app.post('/api/security/reset', (req, res) => {
  incidents = [];
  systemLockdown = false;
  lockdownExpiry = null;
  consecutiveThreats = 0;
  res.json({ success: true, message: 'Security simulator console and state reset successfully.' });
});

// Webhook endpoint to receive alerts from Falcosidekick
app.post('/api/security/events', (req, res) => {
  const event = req.body;
  
  // Construct incident representation
  const newIncident = {
    id: 'falco-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    timestamp: event.time || new Date().toISOString(),
    source: 'Falco eBPF Probe',
    type: event.rule || 'Kernel Syscall Alert',
    message: event.output || 'No output text provided',
    priority: event.priority || 'WARNING',
    fields: event.output_fields || {},
    mitigation: 'Forwarded to Falco Talon Response Engine',
    status: 'Flagged'
  };

  incidents.unshift(newIncident);
  console.log(`[Falco Alert Received]: ${event.rule} - ${event.output}`);
  res.json({ success: true, message: 'Falco alert logged successfully' });
});

// Webhook endpoint to receive mitigation updates from Falco Talon
app.post('/api/talon/events', (req, res) => {
  const talonEvent = req.body;
  
  // Construct talon incident representation
  const newIncident = {
    id: 'talon-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    timestamp: new Date().toISOString(),
    source: 'Falco Talon Active Response',
    type: talonEvent.rule || 'Talon Remediation Action',
    message: `Active Mitigation Rule Triggered: "${talonEvent.rule}". Action: "${talonEvent.action || 'Unknown'}". Actionner: "${talonEvent.actionner || 'Unknown'}".`,
    priority: 'CRITICAL',
    fields: talonEvent,
    mitigation: `Talon executed ${talonEvent.action || 'mitigation'}`,
    status: 'Mitigated'
  };

  incidents.unshift(newIncident);
  console.log(`[Falco Talon Action]: ${talonEvent.rule} - ${talonEvent.action}`);
  res.json({ success: true, message: 'Talon response logged successfully' });
});

// Endpoint to simulate spawning a shell process (triggers Falco: Terminal Spawned)
app.post('/api/threat/spawn-shell', (req, res) => {
  if (checkLockdown()) {
    raspBlockCounter.inc({ threat_type: 'spawn-shell', rule: 'Lockdown' });
    return res.status(403).json({
      success: false,
      blocked: true,
      message: 'Blocked by Application self-protection (RASP): Shell spawning is disabled during active system lockdown.',
      details: 'Containment Mode Active.'
    });
  }

  consecutiveThreats++;
  if (consecutiveThreats >= 3) {
    triggerLockdown();
  }

  exec('/bin/sh -c "whoami"', (err, stdout, stderr) => {
    if (err) {
      threatCounter.inc({ threat_type: 'spawn-shell', status: 'error' });
      return res.status(500).json({ error: err.message });
    }
    threatCounter.inc({ threat_type: 'spawn-shell', status: 'success' });
    
    // Log local RASP detection
    incidents.unshift({
      id: 'rasp-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString(),
      source: 'RASP Engine',
      type: 'Shell Spawning Process Detected',
      message: 'Unrestricted execution of /bin/sh -c "whoami" was requested.',
      priority: 'WARNING',
      fields: { output: stdout.trim() },
      mitigation: 'Logged Syscall & Incremented Threat Counter',
      status: 'Warning'
    });

    res.json({
      success: true,
      message: 'Simulated Shell Spawning executed successfully.',
      output: stdout.trim()
    });
  });
});

// Endpoint to simulate reading a sensitive file (triggers Falco: Read sensitive file untrusted)
app.post('/api/threat/read-sensitive', (req, res) => {
  if (checkLockdown()) {
    raspBlockCounter.inc({ threat_type: 'read-sensitive', rule: 'Lockdown' });
    return res.status(403).json({
      success: false,
      blocked: true,
      message: 'Blocked by Application self-protection (RASP): Sensitive file reading is restricted during active system lockdown.',
      details: 'Containment Mode Active.'
    });
  }

  consecutiveThreats++;
  if (consecutiveThreats >= 3) {
    triggerLockdown();
  }

  fs.readFile('/etc/shadow', 'utf8', (err, data) => {
    // Log local RASP intercept
    incidents.unshift({
      id: 'rasp-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString(),
      source: 'RASP Engine',
      type: 'Sensitive File Access Detected',
      message: 'Attempted read access to the sensitive password shadow file /etc/shadow.',
      priority: 'CRITICAL',
      fields: { error: err ? err.message : 'none' },
      mitigation: err ? 'Access Denied by OS permissions' : 'Caution: File Read Succeeded (Process runs as Root)',
      status: err ? 'Mitigated (OS)' : 'Exploited'
    });

    if (err) {
      threatCounter.inc({ threat_type: 'read-sensitive', status: 'denied' });
      return res.json({
        success: true,
        message: 'System call open() on /etc/shadow intercepted.',
        error: err.message,
        details: 'Even though permission is denied, the kernel syscall was still fired and caught by Falco eBPF!'
      });
    }
    threatCounter.inc({ threat_type: 'read-sensitive', status: 'success' });
    res.json({
      success: true,
      message: 'Successfully read /etc/shadow (running as root - caution!).',
      data: data.substring(0, 50)
    });
  });
});

// Endpoint to simulate writing to a binary directory (triggers Falco: Write below binary dir)
app.post('/api/threat/write-binary', (req, res) => {
  if (checkLockdown()) {
    raspBlockCounter.inc({ threat_type: 'write-binary', rule: 'Lockdown' });
    return res.status(403).json({
      success: false,
      blocked: true,
      message: 'Blocked by Application self-protection (RASP): File modifications inside system directories are forbidden during active system lockdown.',
      details: 'Containment Mode Active.'
    });
  }

  consecutiveThreats++;
  if (consecutiveThreats >= 3) {
    triggerLockdown();
  }

  const filePath = '/bin/hack';
  fs.writeFile(filePath, 'malicious_payload', (err) => {
    if (err) {
      threatCounter.inc({ threat_type: 'write-binary', status: 'denied' });
      incidents.unshift({
        id: 'rasp-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
        timestamp: new Date().toISOString(),
        source: 'RASP Engine',
        type: 'Binary Directory Write Intercepted',
        message: 'Attempted to write malicious binary /bin/hack (write permission denied).',
        priority: 'CRITICAL',
        fields: { path: filePath, error: err.message },
        mitigation: 'Write Denied by OS Permissions',
        status: 'Mitigated (OS)'
      });

      return res.json({
        success: true,
        message: 'System call open(O_WRONLY) on /bin/hack intercepted.',
        error: err.message,
        details: 'Falco rules flag write attempts below binary directories. Caught by eBPF.'
      });
    }

    threatCounter.inc({ threat_type: 'write-binary', status: 'success' });
    
    // Execute Self-Healing Active Response!
    setTimeout(() => {
      fs.unlink(filePath, (unlinkErr) => {
        if (!unlinkErr) {
          incidents.unshift({
            id: 'rasp-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
            timestamp: new Date().toISOString(),
            source: 'RASP Active Response Engine',
            type: 'Self-Healing File Quarantine',
            message: 'Automatically deleted unauthorized binary /bin/hack from system directories.',
            priority: 'HIGH',
            fields: { path: filePath },
            mitigation: 'Automated Quarantine & Deletion',
            status: 'Quarantined'
          });
          console.log('[RASP Active Response]: Deleted /bin/hack successfully (Self-healing).');
        }
      });
    }, 1000);

    incidents.unshift({
      id: 'rasp-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString(),
      source: 'RASP Engine',
      type: 'Unauthorized Write to Binary Directory',
      message: 'Successfully wrote file /bin/hack in a restricted system directory.',
      priority: 'CRITICAL',
      fields: { path: filePath },
      mitigation: 'Self-healing Quarantine scheduled in 1000ms',
      status: 'Vulnerable'
    });

    res.json({
      success: true,
      message: 'Successfully wrote to /bin/hack (running as root - caution!). Self-healing quarantine engaged.'
    });
  });
});

app.listen(PORT, () => {
  console.log(`Backend listening on port ${PORT}`);
});

