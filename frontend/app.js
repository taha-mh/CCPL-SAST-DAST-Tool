/**
 * CCPL Web SAST Dashboard - Real-Time Streaming & Interactive Tab Logic
 *
 * Responsibilities:
 * 1. Fetch available target projects from GET /api/targets on page load.
 * 2. Connect to Server-Sent Events (SSE) stream GET /api/scan/stream on scan trigger.
 * 3. Stream real-time timestamped logs line-by-line into the live console window.
 * 4. Dynamically highlight active pipeline step indicators in the 6-step pathway bar.
 * 5. Support interactive Frontend Filter Tabs (Confirmed Risks vs Discarded False Positives vs All).
 */

let currentScanData = null;
let activeTab = 'confirmed'; // 'confirmed', 'discarded', 'all'

document.addEventListener('DOMContentLoaded', () => {
    fetchTargets();

    const scanBtn = document.getElementById('scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', handleScanSubmit);
    }

    // Attach Tab Switch Handlers
    document.getElementById('tab-confirmed-btn').addEventListener('click', () => setTab('confirmed'));
    document.getElementById('tab-discarded-btn').addEventListener('click', () => setTab('discarded'));
    document.getElementById('tab-all-btn').addEventListener('click', () => setTab('all'));
});


/**
 * Fetches available targets from GET /api/targets and populates dropdown.
 */
async function fetchTargets() {
    const targetSelect = document.getElementById('target-select');
    try {
        const response = await fetch('/api/targets');
        const data = await response.json();

        if (data.targets && data.targets.length > 0) {
            targetSelect.innerHTML = '';
            data.targets.forEach(target => {
                const opt = document.createElement('option');
                opt.value = target;
                opt.textContent = target;
                targetSelect.appendChild(opt);
            });
        } else {
            targetSelect.innerHTML = '<option value="">No targets found in targets/</option>';
        }
    } catch (err) {
        console.error('Failed to fetch target projects:', err);
        targetSelect.innerHTML = '<option value="DVWA">DVWA (Default)</option>';
    }
}


/**
 * Handles "Start SAST Scan" button click, connects to SSE stream GET /api/scan/stream.
 */
function handleScanSubmit() {
    const targetName = document.getElementById('target-select').value || 'DVWA';
    const scanMode = document.getElementById('scan-mode').value;
    const includePattern = document.getElementById('include-pattern').value || '*.php';

    // UI Elements
    const scanBtn = document.getElementById('scan-btn');
    const spinnerGroup = document.getElementById('spinner-container');
    const consoleWrapper = document.getElementById('console-wrapper');
    const consoleOutput = document.getElementById('console-output');
    const reportActions = document.getElementById('report-actions');
    const tabNavigation = document.getElementById('tab-navigation');
    const findingsContainer = document.getElementById('findings-container');

    // Reset UI state
    spinnerGroup.classList.remove('hidden');
    consoleWrapper.classList.remove('hidden');
    consoleOutput.innerHTML = '';
    reportActions.classList.add('hidden');
    tabNavigation.classList.add('hidden');
    findingsContainer.innerHTML = '';
    resetPipelineSteps();

    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span>⏳</span><span>Scanning Target...</span>';

    // Build SSE URL
    const streamUrl = `/api/scan/stream?target_name=${encodeURIComponent(targetName)}&max_findings=${encodeURIComponent(scanMode)}&include_pattern=${encodeURIComponent(includePattern)}`;
    const eventSource = new EventSource(streamUrl);

    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'log') {
            appendConsoleLog(data.timestamp, data.message, data.level);
            updatePipelineStep(data.active_step);
        } else if (data.type === 'result') {
            eventSource.close();
            spinnerGroup.classList.add('hidden');
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<span>⚡</span><span>Start SAST Scan</span>';
            updatePipelineStep('done');
            
            currentScanData = data;
            renderDashboard(data);
        } else if (data.type === 'error') {
            eventSource.close();
            spinnerGroup.classList.add('hidden');
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<span>⚡</span><span>Start SAST Scan</span>';
            appendConsoleLog(new Date().toLocaleTimeString(), `❌ ${data.message}`, 'error');
        }
    };

    eventSource.onerror = (err) => {
        console.error('SSE Stream Error:', err);
        eventSource.close();
        spinnerGroup.classList.add('hidden');
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<span>⚡</span><span>Start SAST Scan</span>';
        appendConsoleLog(new Date().toLocaleTimeString(), '❌ Connection to scan pipeline stream lost.', 'error');
    };
}


/**
 * Appends a timestamped line to the live terminal console output window.
 */
function appendConsoleLog(timestamp, message, level = 'info') {
    const consoleOutput = document.getElementById('console-output');
    const line = document.createElement('div');
    line.className = `console-line ${level}`;

    const isSuccess = message.startsWith('✅') || message.startsWith('🚀');
    if (isSuccess) line.className += ' success';

    let formattedMsg = message.replace(/(\[Step \d\/6\])/g, '<span class="tag">$1</span>');

    line.innerHTML = `<span class="ts">[${timestamp}]</span> ${formattedMsg}`;
    consoleOutput.appendChild(line);
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
}


/**
 * Resets step indicator bar classes.
 */
function resetPipelineSteps() {
    const steps = ['scanner', 'normalizer', 'context', 'assessor', 'reviewer', 'reports'];
    steps.forEach(s => {
        const el = document.getElementById(`step-${s}`);
        if (el) el.className = 'step-item';
    });
}


/**
 * Dynamically highlights active and completed steps in the 6-step pathway bar.
 */
function updatePipelineStep(activeStep) {
    const stepOrder = ['scanner', 'normalizer', 'context', 'assessor', 'reviewer', 'reports'];
    const activeIndex = stepOrder.indexOf(activeStep);

    stepOrder.forEach((step, idx) => {
        const el = document.getElementById(`step-${step}`);
        if (!el) return;

        if (activeStep === 'done') {
            el.className = 'step-item completed';
        } else if (idx < activeIndex) {
            el.className = 'step-item completed';
        } else if (idx === activeIndex) {
            el.className = 'step-item active';
        } else {
            el.className = 'step-item';
        }
    });
}


/**
 * Renders summary metrics, tab counters, and shows findings for active tab.
 */
function renderDashboard(data) {
    const total = data.total_evaluated || 0;
    const confirmed = data.confirmed_vulnerabilities || 0;
    const discarded = data.discarded_false_positives || 0;

    // Update metric numbers
    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-confirmed').textContent = confirmed;
    document.getElementById('stat-discarded').textContent = discarded;

    // Update Tab Counts
    document.getElementById('tab-confirmed-count').textContent = confirmed;
    document.getElementById('tab-discarded-count').textContent = discarded;
    document.getElementById('tab-all-count').textContent = total;

    // Show Report Actions & Filter Tabs
    document.getElementById('report-actions').classList.remove('hidden');
    document.getElementById('tab-navigation').classList.remove('hidden');

    renderActiveTabFindings();
}


/**
 * Sets active tab ('confirmed', 'discarded', 'all') and re-renders findings.
 */
function setTab(tabName) {
    activeTab = tabName;
    
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`tab-${tabName}-btn`).classList.add('active');

    renderActiveTabFindings();
}


/**
 * Filters findings based on activeTab and renders cards.
 */
function renderActiveTabFindings() {
    if (!currentScanData) return;

    const container = document.getElementById('findings-container');
    container.innerHTML = '';

    const allFindings = currentScanData.reviewed_findings || [];
    
    let filtered = [];
    if (activeTab === 'confirmed') {
        filtered = allFindings.filter(f => {
            const dec = f.llm_review?.decision || (f.llm_assessment?.is_plausible ? 'confirmed' : 'rejected');
            return dec === 'confirmed';
        });
    } else if (activeTab === 'discarded') {
        filtered = allFindings.filter(f => {
            const dec = f.llm_review?.decision || (f.llm_assessment?.is_plausible ? 'confirmed' : 'rejected');
            return dec !== 'confirmed';
        });
    } else {
        filtered = allFindings;
    }

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="card empty-state">
                <h3>No findings in this section (${activeTab.toUpperCase()}).</h3>
            </div>
        `;
        return;
    }

    filtered.forEach(f => {
        const review = f.llm_review || {};
        const assessment = f.llm_assessment || {};

        const decision = review.decision || (assessment.is_plausible ? 'confirmed' : 'rejected');
        const isConfirmed = decision === 'confirmed';

        const sev = (review.final_severity || assessment.severity || f.scanner_severity || 'LOW').toUpperCase();
        const badgeClass = isConfirmed ? 'badge-high' : 'badge-low';
        const badgeLabel = isConfirmed ? `CONFIRMED [${sev}]` : `DISCARDED FALSE POSITIVE`;

        const reason = review.review_reason || assessment.reasoning || 'No explanation provided.';
        const remediation = assessment.remediation || 'No remediation snippet available.';

        const card = document.createElement('div');
        card.className = 'finding-card';
        if (!isConfirmed) {
            card.style.borderLeft = '4px solid var(--accent-green-text)';
        }

        card.innerHTML = `
            <div class="finding-header">
                <div>
                    <span class="badge ${badgeClass}">${badgeLabel}</span>
                    <strong style="margin-left: 0.5rem; font-size: 1.1rem;">${f.finding_id}: ${f.title}</strong>
                </div>
            </div>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-top: 0.4rem;">
                <strong>File:</strong> <code>${f.file_path}</code> (Lines ${f.start_line}-${f.end_line}) | <strong>Rule:</strong> <code>${f.rule_id}</code>
            </p>

            <div class="reasoning-box" style="${!isConfirmed ? 'background: var(--accent-green-bg); border-left-color: var(--accent-green-text); color: var(--accent-green-text);' : ''}">
                <strong>🤖 AI Security Reasoning:</strong>
                <p style="margin-top: 0.4rem;">${reason}</p>
            </div>

            ${isConfirmed ? `
                <strong>🛠️ Remediation Recommendation:</strong>
                <pre><code>${remediation}</code></pre>
            ` : ''}

            <strong style="display: block; margin-top: 0.75rem;">📄 Source Code Context:</strong>
            <pre><code>${f.code_context || 'No code context snippet available.'}</code></pre>
        `;

        container.appendChild(card);
    });
}
