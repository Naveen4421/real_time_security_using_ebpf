// Detect backend API endpoint based on host
// Relative path allows Nginx ingress proxying in Kubernetes
const API_BASE = window.location.port === '3000' || window.location.port === '8080'
    ? 'http://localhost:5000'
    : window.location.origin;

const consoleLogs = document.getElementById('console-logs');
const backendStatus = document.getElementById('backend-status');

// Log printing utility
function addLog(message, type = 'info', extraData = null) {
    const logElement = document.createElement('div');
    logElement.classList.add('log-line', type);
    
    const timestamp = new Date().toLocaleTimeString();
    logElement.textContent = `[${timestamp}] ${message}`;
    
    consoleLogs.appendChild(logElement);
    
    if (extraData) {
        const jsonElement = document.createElement('div');
        jsonElement.classList.add('log-line', 'json');
        jsonElement.textContent = JSON.stringify(extraData, null, 2);
        consoleLogs.appendChild(jsonElement);
    }
    
    // Auto scroll to bottom
    const container = consoleLogs.parentElement;
    container.scrollTop = container.scrollHeight;
}

// Connection Health Checking
async function checkHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        
        if (data.status === 'OK') {
            backendStatus.innerHTML = `
                <span class="status-indicator online"></span>
                <span class="status-text">Backend: Connected</span>
            `;
            return true;
        }
    } catch (e) {
        backendStatus.innerHTML = `
            <span class="status-indicator offline"></span>
            <span class="status-text">Backend: Disconnected</span>
        `;
    }
    return false;
}

// Event Triggers
async function triggerThreat(endpoint, threatName) {
    addLog(`Triggering Security Threat: "${threatName}"`, 'trigger');
    try {
        const response = await fetch(`${API_BASE}/api/threat/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        
        if (data.success) {
            addLog(`API Response: Syscall executed. Threat simulation registered.`, 'success', data);
        } else {
            addLog(`Error triggering threat: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (err) {
        addLog(`Network error contacting Backend: ${err.message}`, 'error');
    }
}

// Hook Buttons
document.getElementById('btn-shell').addEventListener('click', () => {
    triggerThreat('spawn-shell', 'Spawn Web Shell');
});

document.getElementById('btn-sensitive').addEventListener('click', () => {
    triggerThreat('read-sensitive', 'Read /etc/shadow');
});

document.getElementById('btn-binary').addEventListener('click', () => {
    triggerThreat('write-binary', 'Write to /bin/hack');
});

document.getElementById('btn-clear').addEventListener('click', () => {
    consoleLogs.innerHTML = `
        <div class="log-line system">[SYSTEM] Console cleared.</div>
    `;
});

// Periodic Connection Check
checkHealth();
setInterval(checkHealth, 5000);
