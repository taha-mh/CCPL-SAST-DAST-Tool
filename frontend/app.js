/**
 * CCPL Web SAST Dashboard - Frontend JavaScript Logic
 *
 * Responsibilities:
 * 1. Fetch available target projects from GET /api/targets on page load.
 * 2. Handle "Start SAST Scan" form submission and call POST /api/scan.
 * 3. Show live loading progress spinner during 6-step pipeline execution.
 * 4. Dynamically render summary metrics and findings cards upon completion.
 */

document.addEventListener('DOMContentLoaded', () => {
    fetchTargets();

    const scanBtn = document.getElementById('scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', handleScanSubmit);
    }
});


/**
 * Fetches available targets from FastAPI GET /api/targets and populates dropdown.
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
 * Handles "Start SAST Scan" button click, triggers POST /api/scan.
 */
async function handleScanSubmit() {
    const targetName = document.getElementById('target-select').value;
    const scanMode = document.getElementById('scan-mode').value;
    const includePattern = document.getElementById('include-pattern').value;

    const maxFindings = scanMode === 'all' ? null : parseInt(scanMode);

    // Show Loading Spinner, hide empty state / previous findings
    const spinner = document.getElementById('loading-spinner');
    const container = document.getElementById('findings-container');
    const reportActions = document.getElementById('report-actions');
    const scanBtn = document.getElementById('scan-btn');

    spinner.classList.remove('hidden');
    container.innerHTML = '';
    reportActions.classList.add('hidden');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '⏳ Scanning Target...';

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target_name: targetName || 'DVWA',
                max_findings: maxFindings,
                include_pattern: includePattern || '*.php'
            })
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.detail || 'Pipeline execution failed');
        }

        const data = await response.json();
        renderResults(data);

    } catch (err) {
        console.error('Scan execution error:', err);
        container.innerHTML = `
            <div class="card" style="border-color: #ef4444;">
                <h3 style="color: #ef4444;">❌ Scan Execution Failed</h3>
                <p style="margin-top: 0.5rem;">${err.message}</p>
            </div>
        `;
    } finally {
        spinner.classList.add('hidden');
        scanBtn.disabled = false;
        scanBtn.innerHTML = '🚀 Start SAST Scan';
    }
}


/**
 * Renders summary metrics, download action bar, and finding cards.
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
                <h3>No findings detected in the selected sample.</h3>
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
            <p style="color: var(--text-muted); font-size: 0.88rem;">
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
