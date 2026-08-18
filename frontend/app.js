/**
 * CCPL Web Security Dashboard - Real-Time Streaming & Interactive Tab Logic
 *
 * Responsibilities:
 * 1. Fetch available target projects from GET /api/targets on page load.
 * 2. Connect to Server-Sent Events (SSE) stream GET /api/scan/stream on scan trigger.
 * 3. Stream real-time timestamped logs line-by-line into the live console window.
 * 4. Dynamically highlight active pipeline step indicators in the 6-step pathway bar.
 * 5. Support interactive Frontend Filter Tabs (Confirmed Risks vs False Positives vs Requires Verification vs All).
 */

let currentScanData = null;
let activeTab = 'confirmed'; // 'confirmed', 'discarded', 'needs_review', 'all'

document.addEventListener('DOMContentLoaded', () => {
    fetchTargets();
    fetchMobileApks();

    const scanBtn = document.getElementById('scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', handleScanSubmit);
    }

    document.querySelectorAll('.pipeline-option').forEach(option => {
        option.addEventListener('click', () => selectPipeline(option.dataset.pipeline));
    });
    document.getElementById('apk-source-select')?.addEventListener('change', event => {
        const uploadMode = event.target.value === 'upload';
        document.getElementById('target-apk-group')?.classList.toggle('hidden', uploadMode);
        document.getElementById('upload-apk-group')?.classList.toggle('hidden', !uploadMode);
    });
    selectPipeline('web_sast');

    // Attach Tab Switch Handlers
    document.getElementById('tab-confirmed-btn').addEventListener('click', () => setTab('confirmed'));
    document.getElementById('tab-discarded-btn').addEventListener('click', () => setTab('discarded'));
    document.getElementById('tab-needs-review-btn').addEventListener('click', () => setTab('needs_review'));
    document.getElementById('tab-all-btn').addEventListener('click', () => setTab('all'));

    // Attach Clickable Stat Card Navigation Handlers
    document.getElementById('card-click-confirmed').addEventListener('click', () => setTab('confirmed'));
    document.getElementById('card-click-discarded').addEventListener('click', () => setTab('discarded'));
    document.getElementById('card-click-needs-review').addEventListener('click', () => setTab('needs_review'));
    document.getElementById('card-click-all').addEventListener('click', () => setTab('all'));
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
        console.error('Failed to fetch APK targets:', error);
        select.innerHTML = '<option value="">Unable to load APK targets</option>';
    }
}


function selectPipeline(pipeline) {
    document.getElementById('pipeline-select').value = pipeline;
    document.querySelectorAll('.pipeline-option').forEach(option => {
        const selected = option.dataset.pipeline === pipeline;
        option.classList.toggle('active', selected);
        option.setAttribute('aria-pressed', selected ? 'true' : 'false');
    });
    const isDast = pipeline === 'web_dast';
    const isMobile = pipeline === 'mobile_sast';
    document.getElementById('target-select-group')?.classList.toggle('hidden', isDast || isMobile);
    document.getElementById('include-pattern-group')?.classList.toggle('hidden', isDast || isMobile);
    document.getElementById('mobile-apk-controls')?.classList.toggle('hidden', !isMobile);
    updatePipelineLabels(pipeline);
}


function updatePipelineLabels(pipeline) {
    const labels = [...document.querySelectorAll('#pipeline-pathway .step-label')];
    const values = pipeline === 'mobile_sast'
        ? ['MobSF Scan', 'Normalization', 'APK Evidence', 'OpenAI Assessor', 'OpenAI Reviewer', 'Mobile Report']
        : pipeline === 'web_dast'
            ? ['OWASP ZAP Scan', 'Normalization', 'HTTP Evidence', 'AI Assessor', 'AI Reviewer', 'Web Report']
            : ['Semgrep Scan', 'Normalization', 'Source Context', 'AI Assessor', 'AI Reviewer', 'Web Report'];
    labels.forEach((label, index) => { label.textContent = values[index]; });
}


/**
 * Handles "Start Scan Pipeline" button click, connects to SSE stream GET /api/scan/stream.
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
    scanBtn.innerHTML = '<span>Scanning Target...</span>';

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
            appendConsoleLog(new Date().toLocaleTimeString(), 'Uploading APK to temporary CCPL storage...', 'info');
            const formData = new FormData();
            formData.append('file', file);
            try {
                const response = await fetch('/api/mobile/apks/upload', { method: 'POST', body: formData });
                const payload = await response.json();
                if (!response.ok) throw new Error(payload.detail || `Upload failed: HTTP ${response.status}`);
                apkReference = payload.token;
                appendConsoleLog(new Date().toLocaleTimeString(), `APK accepted: ${payload.filename}`, 'success');
            } catch (error) {
                restoreScanButton(error.message);
                return;
            }
        }
    }

    // Build SSE URL
    const params = new URLSearchParams({
        target_name: targetName,
        max_findings: scanMode,
        include_pattern: includePattern,
        pipeline,
    });
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
            scanBtn.innerHTML = '<span>Start Scan Pipeline</span>';
            updatePipelineStep('done');
            
            currentScanData = data;
            renderDashboard(data);
        } else if (data.type === 'error') {
            eventSource.close();
            spinnerGroup.classList.add('hidden');
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<span>Start Scan Pipeline</span>';
            appendConsoleLog(new Date().toLocaleTimeString(), `Error: ${data.message}`, 'error');
        }
    };

    eventSource.onerror = (err) => {
        console.error('SSE Stream Error:', err);
        eventSource.close();
        spinnerGroup.classList.add('hidden');
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<span>Start Scan Pipeline</span>';
        appendConsoleLog(new Date().toLocaleTimeString(), 'Connection to scan pipeline stream lost.', 'error');
    };
}


function restoreScanButton(message) {
    document.getElementById('spinner-container')?.classList.add('hidden');
    const button = document.getElementById('scan-btn');
    button.disabled = false;
    button.innerHTML = '<span>Start Scan Pipeline</span>';
    appendConsoleLog(new Date().toLocaleTimeString(), `Error: ${message}`, 'error');
}


/**
 * Appends a timestamped line to the live terminal console output window.
 */
function appendConsoleLog(timestamp, message, level = 'info') {
    const consoleOutput = document.getElementById('console-output');
    const line = document.createElement('div');
    line.className = `console-line ${level}`;

    const isSuccess = message.startsWith('Step ') || message.startsWith('Starting ');
    if (isSuccess) line.className += ' success';

    let formattedMsg = escapeHtml(String(message)).replace(/(\[Step \d\/6\])/g, '<span class="tag">$1</span>');

    line.innerHTML = `<span class="ts">[${escapeHtml(String(timestamp))}]</span> ${formattedMsg}`;
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
    const allFindings = data.reviewed_findings || [];
    const total = data.total_evaluated || allFindings.length;

    const confirmed = data.confirmed_vulnerabilities ?? allFindings.filter(f => findingDecision(f) === 'confirmed').length;
    const discarded = data.rejected_false_positives ?? allFindings.filter(f => findingDecision(f) === 'rejected').length;
    const needsReview = data.requires_manual_verification ?? (total - confirmed - discarded);

    // Update metric numbers
    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-confirmed').textContent = confirmed;
    document.getElementById('stat-discarded').textContent = discarded;
    document.getElementById('stat-needs-review').textContent = needsReview;

    // Update Tab Counts
    document.getElementById('tab-confirmed-count').textContent = confirmed;
    document.getElementById('tab-discarded-count').textContent = discarded;
    document.getElementById('tab-needs-review-count').textContent = needsReview;
    document.getElementById('tab-all-count').textContent = total;

    const mobileReport = data.pipeline === 'mobile_sast';
    document.getElementById('download-html-btn').href = mobileReport ? '/api/reports/mobile/html' : '/api/reports/html';
    document.getElementById('download-md-btn').href = mobileReport ? '/api/reports/mobile/md' : '/api/reports/md';

    // Show Report Actions & Filter Tabs
    document.getElementById('report-actions').classList.remove('hidden');
    document.getElementById('tab-navigation').classList.remove('hidden');

    renderActiveTabFindings();
}


/**
 * Sets active tab ('confirmed', 'discarded', 'needs_review', 'all') and re-renders findings.
 */
function setTab(tabName) {
    activeTab = tabName;
    
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    const btn = document.getElementById(`tab-${tabName}-btn`);
    if (btn) btn.classList.add('active');

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
            return findingDecision(f) === 'confirmed';
        });
    } else if (activeTab === 'discarded') {
        filtered = allFindings.filter(f => {
            const decision = findingDecision(f);
            return decision === 'rejected' || decision === 'discarded';
        });
    } else if (activeTab === 'needs_review') {
        filtered = allFindings.filter(f => {
            return findingDecision(f) === 'needs_review';
        });
    } else {
        filtered = allFindings;
    }

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="card empty-state">
                <h3>No findings in this section (${activeTab.toUpperCase().replace('_', ' ')}).</h3>
            </div>
        `;
        return;
    }

    filtered.forEach(f => {
        const review = f.llm_review || {};
        const assessment = f.llm_assessment || {};

        const decision = findingDecision(f);
        const isConfirmed = decision === 'confirmed';
        const isNeedsReview = decision === 'needs_review';

        const sev = (review.final_severity || assessment.severity || f.scanner_severity || 'LOW').toUpperCase();

        let badgeClass = 'badge-low';
        let badgeLabel = 'FALSE POSITIVE';
        if (isConfirmed) {
            badgeClass = 'badge-high';
            badgeLabel = `CONFIRMED [${sev}]`;
        } else if (isNeedsReview) {
            badgeClass = 'badge-medium';
            badgeLabel = `REQUIRES VERIFICATION [${sev}]`;
        }

        const reason = escapeHtml(review.review_reason || assessment.reasoning || 'No explanation provided.');
        const remediation = escapeHtml(assessment.remediation || 'No remediation snippet available.');
        const ruleId = escapeHtml(f.rule_id || 'UNKNOWN');

        // Domain-aware SAST/DAST/mobile location handling
        const isMobile = f.scan_type === 'mobile_sast' || f.tool === 'MobSF';
        const isDast = !isMobile && !!(f.affected_url || (f.scan_type || '').includes('dast'));
        const locationHtml = isMobile
            ? `<strong>APK location:</strong> <code>${escapeHtml(f.location || f.file_path || f.target || 'Unknown')}</code> | <strong>MobSF rule:</strong> <code>${ruleId}</code>`
            : isDast
            ? `<strong>Target URL:</strong> <code>${escapeHtml(f.affected_url || f.target || 'Unknown')}</code> | <strong>Rule:</strong> <code>${ruleId}</code>`
            : `<strong>File:</strong> <code>${escapeHtml(f.file_path || 'Unknown')}</code> (Lines ${escapeHtml(String(f.start_line ?? '?'))}-${escapeHtml(String(f.end_line ?? '?'))}) | <strong>Rule:</strong> <code>${ruleId}</code>`;
            
        const contextLabel = isMobile ? 'APK Static Evidence Context:' : (isDast ? 'Live HTTP Evidence Context:' : 'Source Code Context:');
        const contextData = escapeHtml(f.evidence_context || f.code_context || 'No context snippet available.');
        const findingTitle = escapeHtml(`${f.finding_id || 'UNKNOWN'}: ${f.title || f.vulnerability_type || 'Security finding'}`);

        const card = document.createElement('div');
        card.className = 'finding-card';
        if (isNeedsReview) {
            card.style.borderLeft = '4px solid var(--accent-yellow)';
        } else if (!isConfirmed) {
            card.style.borderLeft = '4px solid var(--accent-green-text)';
        }

        card.innerHTML = `
            <div class="finding-header">
                <div>
                    <span class="badge ${badgeClass}">${badgeLabel}</span>
                    <strong style="margin-left: 0.5rem; font-size: 1.1rem;">${findingTitle}</strong>
                </div>
            </div>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-top: 0.4rem;">
                ${locationHtml}
            </p>

            <div class="reasoning-box" style="${isNeedsReview ? 'background: rgba(234, 179, 8, 0.1); border-left-color: var(--accent-yellow); color: var(--accent-yellow);' : (!isConfirmed ? 'background: var(--accent-green-bg); border-left-color: var(--accent-green-text); color: var(--accent-green-text);' : '')}">
                <strong>AI Security Reasoning:</strong>
                <p style="margin-top: 0.4rem;">${reason}</p>
            </div>

            ${isConfirmed ? `
                <strong>Remediation Recommendation:</strong>
                <pre><code>${remediation}</code></pre>
            ` : ''}

            <strong style="display: block; margin-top: 0.75rem;">${contextLabel}</strong>
            <pre><code>${contextData}</code></pre>
        `;

        container.appendChild(card);
    });
}


function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, character => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
    })[character]);
}


function findingDecision(finding) {
    const review = finding.llm_review || {};
    if (review.decision) return review.decision;
    if (review.llm_status === 'error') return 'needs_review';
    const assessment = finding.llm_assessment || {};
    if (assessment.llm_status === 'error') return 'needs_review';
    return assessment.is_plausible === true ? 'confirmed' : 'needs_review';
}
