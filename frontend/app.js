/**
 * CCPL Web SAST Dashboard - Real-Time Streaming JavaScript Logic
 *
 * Responsibilities:
 * 1. Fetch available target projects from GET /api/targets on page load.
 * 2. Connect to Server-Sent Events (SSE) stream GET /api/scan/stream on scan trigger.
 * 3. Stream real-time timestamped logs line-by-line into the live console window.
 * 4. Dynamically highlight active pipeline step indicators in the single step bar.
 * 5. Render final summary metrics, report download buttons, and finding cards upon completion.
 */

document.addEventListener('DOMContentLoaded', () => {
    fetchTargets();

    const scanBtn = document.getElementById('scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', handleScanSubmit);
    }
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
    const findingsContainer = document.getElementById('findings-container');

    // Reset UI state
    spinnerGroup.classList.remove('hidden');
    consoleWrapper.classList.remove('hidden');
    consoleOutput.innerHTML = '';
    reportActions.classList.add('hidden');
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
            renderResults(data);
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

    line.innerHTML = `<span class="ts">[${timestamp}]</span> ${message}`;
    consoleOutput.appendChild(line);
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
}


/**
 * Resets step indicator bar classes.
 */
function resetPipelineSteps() {
    const steps = ['scanner', 'normalizer', 'context', 'llm', 'reports'];
    steps.forEach(s => {
        const el = document.getElementById(`step-${s}`);
        if (el) {
            el.className = 'step-item';
        }
    });
}


/**
 * Dynamically highlights active and completed steps in the single step bar.
 */
function updatePipelineStep(activeStep) {
    const stepOrder = ['scanner', 'normalizer', 'context', 'llm', 'reports'];
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
 * Renders summary metrics, download action bar, and finding cards upon completion.
 */
function renderResults(data) {
    // Update summary count badges
    document.getElementById('stat-total').textContent = data.total_evaluated || 0;
    document.getElementById('stat-confirmed').textContent = data.confirmed_vulnerabilities || 0;
    document.getElementById('stat-discarded').textContent = data.discarded_false_positives || 0;

    // Show Report Download Buttons
    const reportActions = document.getElementById('report-actions');
    reportActions.classList.remove('hidden');

    const container = document.getElementById('findings-container');
    const findings = data.reviewed_findings || [];

    if (findings.length === 0) {
        container.innerHTML = `
            <div class="card empty-state">
                <h3>No vulnerabilities detected in the selected target.</h3>
            </div>
        `;
        return;
    }

    // Loop through findings and build HTML cards
    findings.forEach(f => {
        const review = f.llm_review || {};
        const assessment = f.llm_assessment || {};

        const decision = review.decision || (assessment.is_plausible ? 'confirmed' : 'rejected');
        const isConfirmed = decision === 'confirmed';

        const sev = (review.final_severity || assessment.severity || f.scanner_severity || 'LOW').toUpperCase();
        const badgeClass = isConfirmed ? 'badge-high' : 'badge-low';

        const reason = review.review_reason || assessment.reasoning || 'No explanation provided.';
        const remediation = assessment.remediation || 'No remediation snippet available.';

        const card = document.createElement('div');
        card.className = 'finding-card';

        card.innerHTML = `
            <div class="finding-header">
                <div>
                    <span class="badge ${badgeClass}">${decision.toUpperCase()} [${sev}]</span>
                    <strong style="margin-left: 0.5rem; font-size: 1.1rem;">${f.finding_id}: ${f.title}</strong>
                </div>
            </div>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-top: 0.4rem;">
                <strong>File:</strong> <code>${f.file_path}</code> (Lines ${f.start_line}-${f.end_line}) | <strong>Rule:</strong> <code>${f.rule_id}</code>
            </p>

            <div class="reasoning-box">
                <strong>🤖 AI Security Reasoning:</strong>
                <p style="margin-top: 0.4rem;">${reason}</p>
            </div>

            <strong>🛠️ Remediation Recommendation:</strong>
            <pre><code>${remediation}</code></pre>

            <strong style="display: block; margin-top: 0.75rem;">📄 Source Code Context:</strong>
            <pre><code>${f.code_context || 'No code context snippet available.'}</code></pre>
        `;

        container.appendChild(card);
    });
}
