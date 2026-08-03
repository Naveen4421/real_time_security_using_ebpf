const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Backend is running' });
});

// Endpoint to simulate spawning a shell process (triggers Falco: Terminal Spawned)
app.post('/api/threat/spawn-shell', (req, res) => {
  exec('/bin/sh -c "whoami"', (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({
      success: true,
      message: 'Simulated Shell Spawning executed successfully.',
      output: stdout.trim()
    });
  });
});

// Endpoint to simulate reading a sensitive file (triggers Falco: Read sensitive file untrusted)
app.post('/api/threat/read-sensitive', (req, res) => {
  fs.readFile('/etc/shadow', 'utf8', (err, data) => {
    // Note: This will likely fail with Permission Denied if run as non-root user (which is expected and good security!),
    // but the syscall open('/etc/shadow') is still generated and captured by eBPF probe!
    if (err) {
      return res.json({
        success: true,
        message: 'System call open() on /etc/shadow intercepted.',
        error: err.message,
        details: 'Even though permission is denied, the kernel syscall was still fired and caught by Falco eBPF!'
      });
    }
    res.json({
      success: true,
      message: 'Successfully read /etc/shadow (running as root - caution!).',
      data: data.substring(0, 50)
    });
  });
});

// Endpoint to simulate writing to a binary directory (triggers Falco: Write below binary dir)
app.post('/api/threat/write-binary', (req, res) => {
  const filePath = '/bin/hack';
  fs.writeFile(filePath, 'malicious_payload', (err) => {
    if (err) {
      return res.json({
        success: true,
        message: 'System call open(O_WRONLY) on /bin/hack intercepted.',
        error: err.message,
        details: 'Falco rules flag write attempts below binary directories. Caught by eBPF.'
      });
    }
    res.json({
      success: true,
      message: 'Successfully wrote to /bin/hack (running as root - caution!).'
    });
  });
});

app.listen(PORT, () => {
  console.log(`Backend listening on port ${PORT}`);
});
