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
    fetchMobileApks();

    const scanBtn = document.getElementById('scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', handleScanSubmit);
    }

    const pipelineSelect = document.getElementById('pipeline-select');
    if (pipelineSelect) {
        pipelineSelect.addEventListener('change', (e) => {
            const isDast = e.target.value === 'web_dast';
            const isMobile = e.target.value === 'mobile_sast';
            const targetGroup = document.getElementById('target-select-group');
            const patternGroup = document.getElementById('include-pattern-group');
            const mobileControls = document.getElementById('mobile-apk-controls');
            if (isDast || isMobile) {
                if (targetGroup) targetGroup.classList.add('hidden');
                if (patternGroup) patternGroup.classList.add('hidden');
            } else {
                if (targetGroup) targetGroup.classList.remove('hidden');
                if (patternGroup) patternGroup.classList.remove('hidden');
            }
            if (mobileControls) mobileControls.classList.toggle('hidden', !isMobile);
            updatePipelineLabels(isMobile);
        });
    }

    document.getElementById('apk-source-select')?.addEventListener('change', (event) => {
        const uploadMode = event.target.value === 'upload';
        document.getElementById('target-apk-group')?.classList.toggle('hidden', uploadMode);
        document.getElementById('upload-apk-group')?.classList.toggle('hidden', !uploadMode);
    });

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

async function fetchMobileApks() {
    const select = document.getElementById('target-apk-select');
    try {
        const response = await fetch('/api/mobile/apks');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        select.innerHTML = '';
        if (!data.apks?.length) {
            select.innerHTML = '<option value="">No APK files found under targets/</option>';
            return;
        }
        data.apks.forEach(apk => {
            const option = document.createElement('option');
            option.value = apk.reference;
            option.textContent = `${apk.reference} (${(apk.size_bytes / 1024 / 1024).toFixed(2)} MB)`;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to fetch target APK files:', error);
        select.innerHTML = '<option value="">Unable to load target APKs</option>';
    }
}

function updatePipelineLabels(isMobile) {
    const labels = document.querySelectorAll('#pipeline-pathway .step-label');
    const values = isMobile
        ? ['MobSF Scan', 'Normalizing', 'APK Evidence', 'AI Assessor (Pass 1)', 'AI Reviewer (Pass 2)', 'Report Generator']
        : ['Semgrep Scan', 'Normalizing', 'Source Context', 'AI Assessor (Pass 1)', 'AI Reviewer (Pass 2)', 'Report Generator'];
    labels.forEach((label, index) => { label.textContent = values[index]; });
}


/**
 * Handles "Start SAST Scan" button click, connects to SSE stream GET /api/scan/stream.
 */
async function handleScanSubmit() {
    const pipeline = document.getElementById('pipeline-select').value || 'web_sast';
    const targetName = document.getElementById('target-select').value || 'DVWA';
    const scanMode = document.getElementById('scan-mode').value;
    const includePattern = document.getElementById('include-pattern').value || '*.php';
    let apkSource = '';
    let apkReference = '';

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

    if (pipeline === 'mobile_sast') {
        apkSource = document.getElementById('apk-source-select').value;
        if (apkSource === 'target') {
            apkReference = document.getElementById('target-apk-select').value;
            if (!apkReference) {
                restoreScanButton('Select an APK from targets/ first.');
                return;
            }
        } else {
            const file = document.getElementById('apk-file-input').files[0];
            if (!file) {
                restoreScanButton('Choose an APK file first.');
                return;
            }
            appendConsoleLog(new Date().toLocaleTimeString(), 'Uploading APK securely to the CCPL backend...', 'info');
            const formData = new FormData();
            formData.append('file', file);
            try {
                const uploadResponse = await fetch('/api/mobile/apks/upload', { method: 'POST', body: formData });
                const uploadData = await uploadResponse.json();
                if (!uploadResponse.ok) throw new Error(uploadData.detail || `Upload failed: HTTP ${uploadResponse.status}`);
                apkReference = uploadData.token;
                appendConsoleLog(new Date().toLocaleTimeString(), `APK uploaded: ${uploadData.filename}`, 'success');
            } catch (error) {
                restoreScanButton(error.message);
                return;
            }
        }
    }

    // Build SSE URL
    const params = new URLSearchParams({ target_name: targetName, max_findings: scanMode, include_pattern: includePattern, pipeline });
    if (pipeline === 'mobile_sast') {
        params.set('apk_source', apkSource);
        params.set('apk_reference', apkReference);
    }
    const streamUrl = `/api/scan/stream?${params.toString()}`;
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
            scanBtn.innerHTML = '<span>⚡</span><span>Start Scan Pipeline</span>';
            updatePipelineStep('done');
            
            currentScanData = data;
            renderDashboard(data);
        } else if (data.type === 'error') {
            eventSource.close();
            spinnerGroup.classList.add('hidden');
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<span>⚡</span><span>Start Scan Pipeline</span>';
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

function restoreScanButton(errorMessage) {
    document.getElementById('spinner-container')?.classList.add('hidden');
    const button = document.getElementById('scan-btn');
    button.disabled = false;
    button.innerHTML = '<span>⚡</span><span>Start Scan Pipeline</span>';
    appendConsoleLog(new Date().toLocaleTimeString(), `❌ ${errorMessage}`, 'error');
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

        // Dual SAST/DAST location handling
        const isDast = !!f.target;
        const locationHtml = isDast 
            ? `<strong>Target URL:</strong> <code>${f.target}</code> | <strong>Rule:</strong> <code>${f.rule_id}</code>`
            : `<strong>File:</strong> <code>${f.file_path}</code> (Lines ${f.start_line}-${f.end_line}) | <strong>Rule:</strong> <code>${f.rule_id}</code>`;
            
        const contextLabel = isDast ? '📄 Live HTTP Evidence Context:' : '📄 Source Code Context:';
        const contextData = f.evidence_context || f.code_context || 'No context snippet available.';

        const card = document.createElement('div');
        card.className = 'finding-card';
        if (!isConfirmed) {
            card.style.borderLeft = '4px solid var(--accent-green-text)';
        }

        card.innerHTML = `
            <div class="finding-header">
                <div>
                    <span class="badge ${badgeClass}">${badgeLabel}</span>
                    <strong style="margin-left: 0.5rem; font-size: 1.1rem;">${f.finding_id}: ${f.title || f.vulnerability_type}</strong>
                </div>
            </div>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-top: 0.4rem;">
                ${locationHtml}
            </p>

            <div class="reasoning-box" style="${!isConfirmed ? 'background: var(--accent-green-bg); border-left-color: var(--accent-green-text); color: var(--accent-green-text);' : ''}">
                <strong>🤖 AI Security Reasoning:</strong>
                <p style="margin-top: 0.4rem;">${reason}</p>
            </div>

            ${isConfirmed ? `
                <strong>🛠️ Remediation Recommendation:</strong>
                <pre><code>${remediation}</code></pre>
            ` : ''}

            <strong style="display: block; margin-top: 0.75rem;">${contextLabel}</strong>
            <pre><code>${contextData}</code></pre>
        `;

        container.appendChild(card);
    });
}
