// Detect backend API endpoint based on host
const API_BASE = window.location.port === '3000' || window.location.port === '8080'
    ? 'http://localhost:5000'
    : window.location.origin;

// DOM Elements
const consoleLogs = document.getElementById('console-logs');
const backendStatus = document.getElementById('backend-status');
const shieldStatus = document.getElementById('shield-status');
const shieldModeBadge = document.getElementById('shield-mode-badge');
const threatCounterVal = document.getElementById('threat-counter-val');
const threatProgress = document.getElementById('threat-progress');
const lockdownStatusVal = document.getElementById('lockdown-status-val');
const lockdownTimerVal = document.getElementById('lockdown-timer-val');
const incidentsFeed = document.getElementById('incidents-feed');

// Buttons
const btnShell = document.getElementById('btn-shell');
const btnSensitive = document.getElementById('btn-sensitive');
const btnBinary = document.getElementById('btn-binary');
const btnClear = document.getElementById('btn-clear');
const btnResetShield = document.getElementById('btn-reset-shield');

// Cache to prevent redrawing unchanged incidents list
let lastIncidentsJson = '';

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

// Poll Security Status (RASP shield & Lockdown state)
async function pollSecurityStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/security/status`);
        if (!response.ok) return;
        const status = await response.json();

        // Update threat counter and progress bar
        const count = status.threatCount || 0;
        threatCounterVal.textContent = `${count} / 3`;
        threatProgress.style.width = `${Math.min(100, (count / 3) * 100)}%`;

        if (status.lockdown) {
            shieldModeBadge.textContent = 'Status: Containment';
            shieldModeBadge.className = 'badge badge-danger';
            
            shieldStatus.innerHTML = `
                <span class="status-indicator warning"></span>
                <span class="status-text">Shield: Lockdown Active</span>
            `;

            lockdownStatusVal.textContent = 'ACTIVE';
            lockdownStatusVal.classList.add('danger-text');
            lockdownTimerVal.textContent = `Containment route blocks: ${status.lockdownRemainingSeconds}s remaining`;
        } else {
            shieldModeBadge.textContent = 'Status: Monitoring';
            shieldModeBadge.className = 'badge badge-purple';

            shieldStatus.innerHTML = `
                <span class="status-indicator online"></span>
                <span class="status-text">Shield: Active</span>
            `;

            lockdownStatusVal.textContent = 'INACTIVE';
            lockdownStatusVal.classList.remove('danger-text');
            lockdownTimerVal.textContent = 'System Operating Normally';
        }
    } catch (err) {
        console.error('Error polling security status:', err);
    }
}

// Poll Incident feed
async function pollIncidents() {
    try {
        const response = await fetch(`${API_BASE}/api/security/incidents`);
        if (!response.ok) return;
        const data = await response.json();

        // Stringify to compare with last render to avoid flickering
        const currentJson = JSON.stringify(data);
        if (currentJson === lastIncidentsJson) return;
        lastIncidentsJson = currentJson;

        renderIncidents(data);
    } catch (err) {
        console.error('Error polling incidents:', err);
    }
}

// Render incident timeline elements
function renderIncidents(incidents) {
    incidentsFeed.innerHTML = '';

    if (!incidents || incidents.length === 0) {
        incidentsFeed.innerHTML = `
            <div class="empty-feed-placeholder">
                <span class="placeholder-icon">🛡️</span>
                <p>No security incidents flagged yet. Trigger threats on the left to activate eBPF probes and active responses.</p>
            </div>
        `;
        return;
    }

    incidents.forEach(inc => {
        const card = document.createElement('div');
        card.className = 'incident-card';

        // Apply visual classes based on priority or type
        let priorityClass = 'info';
        if (inc.priority === 'CRITICAL' || inc.priority === 'HIGH') {
            priorityClass = 'critical';
        } else if (inc.priority === 'WARNING') {
            priorityClass = 'warning';
        }

        if (inc.status === 'Mitigated' || inc.status === 'Quarantined' || inc.status === 'Resolved') {
            card.classList.add('mitigated');
        } else {
            card.classList.add(priorityClass);
        }

        // Parse timestamp
        const timeStr = new Date(inc.timestamp).toLocaleTimeString();

        // Build Inner HTML
        card.innerHTML = `
            <div class="incident-header">
                <span class="incident-title">${escapeHtml(inc.type)}</span>
                <div class="incident-meta">
                    <span class="source-tag">${escapeHtml(inc.source)}</span>
                    <span class="priority-tag ${priorityClass}">${escapeHtml(inc.priority)}</span>
                </div>
            </div>
            <div class="incident-body">${escapeHtml(inc.message)}</div>
            ${inc.mitigation ? `<div class="incident-mitigation">Response Action: ${escapeHtml(inc.mitigation)} (${escapeHtml(inc.status)})</div>` : ''}
            <div class="incident-time">${timeStr}</div>
        `;

        incidentsFeed.appendChild(card);
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Event Triggers
async function triggerThreat(endpoint, threatName) {
    addLog(`Triggering Security Threat: "${threatName}"`, 'trigger');
    try {
        const response = await fetch(`${API_BASE}/api/threat/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const isJson = response.headers.get('content-type')?.includes('application/json');
        const data = isJson ? await response.json() : null;

        if (response.ok && data && data.success) {
            addLog(`API Response: Syscall executed. Threat simulation registered.`, 'success', data);
        } else if (response.status === 403 && data && data.blocked) {
            addLog(`RASP Block: Threat execution prevented.`, 'error', data);
        } else {
            const errMsg = data ? (data.error || data.message) : 'Server returned error status';
            addLog(`Execution Alert: ${errMsg}`, 'error', data);
        }
        
        // Immediate poll status update
        pollSecurityStatus();
        pollIncidents();
    } catch (err) {
        addLog(`Network error contacting Backend: ${err.message}`, 'error');
    }
}

// Administrative Resets
async function resetShield() {
    addLog('Reset request sent. Cleaning console logs and containment states...', 'system');
    try {
        const response = await fetch(`${API_BASE}/api/security/reset`, { method: 'POST' });
        const data = await response.json();
        if (data.success) {
            addLog('Console logs and state variables reset successfully.', 'success');
            pollSecurityStatus();
            pollIncidents();
        }
    } catch (err) {
        addLog(`Reset failed: ${err.message}`, 'error');
    }
}

// Event Listeners
btnShell.addEventListener('click', () => triggerThreat('spawn-shell', 'Spawn Web Shell'));
btnSensitive.addEventListener('click', () => triggerThreat('read-sensitive', 'Read /etc/shadow'));
btnBinary.addEventListener('click', () => triggerThreat('write-binary', 'Write to /bin/hack'));
btnResetShield.addEventListener('click', resetShield);

btnClear.addEventListener('click', () => {
    consoleLogs.innerHTML = `
        <div class="log-line system">[SYSTEM] Console cleared.</div>
    `;
});

// Initialization
checkHealth();
pollSecurityStatus();
pollIncidents();

// Periodic Checks
setInterval(checkHealth, 3000);
setInterval(pollSecurityStatus, 1000);
setInterval(pollIncidents, 1000);
