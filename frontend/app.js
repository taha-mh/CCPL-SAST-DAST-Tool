/**
 * CCPL Web Security Dashboard - Real-Time Streaming & Interactive Category View Logic
 *
 * Responsibilities:
 * 1. Fetch available target projects from GET /api/targets on page load.
 * 2. Connect to Server-Sent Events (SSE) stream GET /api/scan/stream on scan trigger.
 * 3. Stream real-time timestamped logs line-by-line into the live console window.
 * 4. Dynamically highlight active pipeline step indicators in the 6-step pathway bar.
 * 5. Support interactive Stat Card Category View ("Back to Summary" navigation).
 */

let currentScanData = null;
let activeCategory = 'confirmed'; // 'confirmed', 'discarded', 'needs_review', 'all'

document.addEventListener('DOMContentLoaded', () => {
    fetchTargets();

    const scanBtn = document.getElementById('scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', handleScanSubmit);
    }

    const pipelineSelect = document.getElementById('pipeline-select');
    if (pipelineSelect) {
        pipelineSelect.addEventListener('change', (e) => {
            const isDast = e.target.value === 'web_dast';
            const targetGroup = document.getElementById('target-select-group');
            const patternGroup = document.getElementById('include-pattern-group');
            const scannerStepLabel = document.getElementById('scanner-step-label');

            if (isDast) {
                if (targetGroup) targetGroup.classList.add('hidden');
                if (patternGroup) patternGroup.classList.add('hidden');
                if (scannerStepLabel) scannerStepLabel.textContent = 'OWASP ZAP Scan';
            } else {
                if (targetGroup) targetGroup.classList.remove('hidden');
                if (patternGroup) patternGroup.classList.remove('hidden');
                if (scannerStepLabel) scannerStepLabel.textContent = 'Semgrep Scan';
            }
        });
    }

    // Attach Clickable Stat Card Category Navigation Handlers
    const cardConfirmed = document.getElementById('card-click-confirmed');
    if (cardConfirmed) cardConfirmed.addEventListener('click', () => openCategoryView('confirmed'));

    const cardDiscarded = document.getElementById('card-click-discarded');
    if (cardDiscarded) cardDiscarded.addEventListener('click', () => openCategoryView('discarded'));

    const cardNeedsReview = document.getElementById('card-click-needs-review');
    if (cardNeedsReview) cardNeedsReview.addEventListener('click', () => openCategoryView('needs_review'));

    const cardAll = document.getElementById('card-click-all');
    if (cardAll) cardAll.addEventListener('click', () => openCategoryView('all'));

    // Attach Back to Summary Button Handler
    const backBtn = document.getElementById('back-to-summary-btn');
    if (backBtn) backBtn.addEventListener('click', closeCategoryView);
});


/**
 * Fetches available targets from GET /api/targets and populates dropdown.
 */
async function fetchTargets() {
    const targetSelect = document.getElementById('target-select');
    if (!targetSelect) return;

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
 * Handles "Start Scan Pipeline" button click, connects to SSE stream GET /api/scan/stream.
 */
function handleScanSubmit(e) {
    if (e && e.preventDefault) e.preventDefault();

    const pipelineSelect = document.getElementById('pipeline-select');
    const targetSelect = document.getElementById('target-select');
    const scanModeSelect = document.getElementById('scan-mode');
    const patternInput = document.getElementById('include-pattern');

    const pipeline = pipelineSelect ? pipelineSelect.value : 'web_sast';
    const targetName = targetSelect ? targetSelect.value || 'DVWA' : 'DVWA';
    const scanMode = scanModeSelect ? scanModeSelect.value : '10';
    const includePattern = patternInput ? patternInput.value || '*.php' : '*.php';

    // UI Elements
    const scanBtn = document.getElementById('scan-btn');
    const spinnerGroup = document.getElementById('spinner-container');
    const consoleWrapper = document.getElementById('console-wrapper');
    const consoleOutput = document.getElementById('console-output');
    const reportActions = document.getElementById('report-actions');

    // Make sure we are in summary view
    closeCategoryView();

    // Reset UI state
    if (spinnerGroup) spinnerGroup.classList.remove('hidden');
    if (consoleWrapper) consoleWrapper.classList.remove('hidden');
    if (consoleOutput) consoleOutput.innerHTML = '';
    if (reportActions) reportActions.classList.add('hidden');
    
    resetPipelineSteps();

    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<span>Scanning Target...</span>';
    }

    // Build SSE URL
    const streamUrl = `/api/scan/stream?target_name=${encodeURIComponent(targetName)}&max_findings=${encodeURIComponent(scanMode)}&include_pattern=${encodeURIComponent(includePattern)}&pipeline=${encodeURIComponent(pipeline)}`;
    const eventSource = new EventSource(streamUrl);

    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'log') {
            appendConsoleLog(data.timestamp, data.message, data.level);
            updatePipelineStep(data.active_step);
        } else if (data.type === 'result') {
            eventSource.close();
            if (spinnerGroup) spinnerGroup.classList.add('hidden');
            if (scanBtn) {
                scanBtn.disabled = false;
                scanBtn.innerHTML = '<span>Start Scan Pipeline</span>';
            }
            updatePipelineStep('done');
            
            currentScanData = data;
            renderDashboardSummary(data);
        } else if (data.type === 'error') {
            eventSource.close();
            if (spinnerGroup) spinnerGroup.classList.add('hidden');
            if (scanBtn) {
                scanBtn.disabled = false;
                scanBtn.innerHTML = '<span>Start Scan Pipeline</span>';
            }
            appendConsoleLog(new Date().toLocaleTimeString(), `Error: ${data.message}`, 'error');
        }
    };

    eventSource.onerror = (err) => {
        console.error('SSE Stream Error:', err);
        eventSource.close();
        if (spinnerGroup) spinnerGroup.classList.add('hidden');
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<span>Start Scan Pipeline</span>';
        }
        appendConsoleLog(new Date().toLocaleTimeString(), 'Connection to scan pipeline stream lost.', 'error');
    };
}


/**
 * Appends a timestamped line to the live terminal console output window.
 */
function appendConsoleLog(timestamp, message, level = 'info') {
    const consoleOutput = document.getElementById('console-output');
    if (!consoleOutput) return;

    const line = document.createElement('div');
    line.className = `console-line ${level}`;

    const isSuccess = message.startsWith('Step ') || message.startsWith('Starting ');
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
 * Renders summary metrics and shows report actions bar.
 */
function renderDashboardSummary(data) {
    const allFindings = data.reviewed_findings || [];
    const total = data.total_evaluated || allFindings.length;

    const confirmed = data.confirmed_vulnerabilities || allFindings.filter(f => (f.llm_review?.decision || (f.llm_assessment?.is_plausible ? 'confirmed' : 'rejected')) === 'confirmed').length;
    const discarded = data.rejected_false_positives || allFindings.filter(f => (f.llm_review?.decision || (f.llm_assessment?.is_plausible ? 'confirmed' : 'rejected')) === 'rejected').length;
    const needsReview = data.requires_manual_verification || (total - confirmed - discarded);

    // Update metric numbers
    const statTotal = document.getElementById('stat-total');
    const statConfirmed = document.getElementById('stat-confirmed');
    const statDiscarded = document.getElementById('stat-discarded');
    const statNeedsReview = document.getElementById('stat-needs-review');

    if (statTotal) statTotal.textContent = total;
    if (statConfirmed) statConfirmed.textContent = confirmed;
    if (statDiscarded) statDiscarded.textContent = discarded;
    if (statNeedsReview) statNeedsReview.textContent = needsReview;

    // Show Report Actions Bar
    const reportActions = document.getElementById('report-actions');
    if (reportActions) reportActions.classList.remove('hidden');
}


/**
 * Opens Category Overlay View for a clicked stat card category.
 */
function openCategoryView(categoryName) {
    activeCategory = categoryName;

    const mainSummary = document.getElementById('main-summary-view');
    const categoryView = document.getElementById('category-view');
    const titleEl = document.getElementById('category-view-title');
    const subtitleEl = document.getElementById('category-view-subtitle');

    if (!categoryView) return;

    const categoryTitles = {
        'confirmed': 'Confirmed Security Risks',
        'discarded': 'Discarded False Positives',
        'needs_review': 'Requires Manual Verification',
        'all': 'All Evaluated Findings'
    };

    const categorySubtitles = {
        'confirmed': 'Verified vulnerabilities backed by observable evidence context.',
        'discarded': 'Scanner noise rejected by AI Reviewer due to proper sanitization or safe headers.',
        'needs_review': 'Findings with incomplete evidence flagged for manual security review.',
        'all': 'Complete list of findings evaluated during the security scan.'
    };

    if (titleEl) titleEl.textContent = categoryTitles[categoryName] || 'Categorized Findings';
    if (subtitleEl) subtitleEl.textContent = categorySubtitles[categoryName] || 'Filtered View';

    // Hide Main Homepage Summary View & Show Only Dedicated Category View Page
    if (mainSummary) mainSummary.classList.add('hidden');
    categoryView.classList.remove('hidden');
    
    renderCategoryFindings();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}


/**
 * Closes Category Overlay View and returns to main homepage summary view.
 */
function closeCategoryView() {
    const categoryView = document.getElementById('category-view');
    const mainSummary = document.getElementById('main-summary-view');

    if (categoryView) categoryView.classList.add('hidden');
    if (mainSummary) mainSummary.classList.remove('hidden');
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
}


/**
 * Filters findings based on activeCategory and renders finding cards into category-findings-container.
 */
function renderCategoryFindings() {
    const container = document.getElementById('category-findings-container');
    if (!container) return;

    container.innerHTML = '';

    if (!currentScanData || !currentScanData.reviewed_findings) {
        container.innerHTML = `
            <div class="card empty-state">
                <h3>No scan data available yet. Please run a scan first.</h3>
            </div>
        `;
        return;
    }

    const allFindings = currentScanData.reviewed_findings || [];
    
    let filtered = [];
    if (activeCategory === 'confirmed') {
        filtered = allFindings.filter(f => {
            const dec = f.llm_review?.decision || (f.llm_assessment?.is_plausible ? 'confirmed' : 'rejected');
            return dec === 'confirmed';
        });
    } else if (activeCategory === 'discarded') {
        filtered = allFindings.filter(f => {
            const dec = f.llm_review?.decision || (f.llm_assessment?.is_plausible ? 'confirmed' : 'rejected');
            return dec === 'rejected' || dec === 'discarded';
        });
    } else if (activeCategory === 'needs_review') {
        filtered = allFindings.filter(f => {
            const dec = f.llm_review?.decision || (f.llm_assessment?.is_plausible ? 'confirmed' : 'rejected');
            return dec === 'needs_review';
        });
    } else {
        filtered = allFindings;
    }

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="card empty-state">
                <h3>No findings in category: ${activeCategory.toUpperCase().replace('_', ' ')}.</h3>
            </div>
        `;
        return;
    }

    filtered.forEach(f => {
        const review = f.llm_review || {};
        const assessment = f.llm_assessment || {};

        const decision = review.decision || (assessment.is_plausible ? 'confirmed' : 'rejected');
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

        const reason = review.review_reason || assessment.reasoning || 'No explanation provided.';
        const remediation = assessment.remediation || 'No remediation snippet available.';

        // Dual SAST/DAST location handling
        const isDast = !!(f.affected_url || f.target);
        const locationHtml = isDast 
            ? `<strong>Target URL:</strong> <code>${f.affected_url || f.target}</code> | <strong>Rule:</strong> <code>${f.rule_id}</code>`
            : `<strong>File:</strong> <code>${f.file_path}</code> (Lines ${f.start_line}-${f.end_line}) | <strong>Rule:</strong> <code>${f.rule_id}</code>`;
            
        const contextLabel = isDast ? 'Live HTTP Evidence Context:' : 'Source Code Context:';
        const contextData = f.evidence_context || f.code_context || 'No context snippet available.';

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
                    <strong style="margin-left: 0.5rem; font-size: 1.1rem;">${f.finding_id}: ${f.title || f.vulnerability_type}</strong>
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
