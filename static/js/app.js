/**
 * PhishGuard AI — Premium Frontend Logic
 * Particle network animation, toast notifications, email generation,
 * red-flag highlighting, and history management.
 */

// ─── State ──────────────────────────────────────────────────────────────────────
let currentEmail = null;
let currentIndicators = [];
let currentParams = null;
let currentEmailId = null;
let redFlagsActive = false;
let emailCount = 0;

// ─── DOM Ready ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initTriggerButtons();
    initParticles();
    loadHistory();
    animateStatCounter();
    checkAIProvider();
});

// ─── Particle Network Animation ─────────────────────────────────────────────────
function initParticles() {
    const canvas = document.getElementById('particleCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let particles = [];
    let mouse = { x: -1000, y: -1000 };
    const PARTICLE_COUNT = 60;
    const CONNECTION_DIST = 150;
    const MOUSE_DIST = 200;

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    window.addEventListener('resize', resize);
    resize();

    document.addEventListener('mousemove', e => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });

    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.vx = (Math.random() - 0.5) * 0.4;
            this.vy = (Math.random() - 0.5) * 0.4;
            this.radius = Math.random() * 1.5 + 0.5;
            this.opacity = Math.random() * 0.4 + 0.1;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
            if (this.y < 0 || this.y > canvas.height) this.vy *= -1;

            // Mouse interaction
            const dx = mouse.x - this.x;
            const dy = mouse.y - this.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < MOUSE_DIST) {
                const force = (MOUSE_DIST - dist) / MOUSE_DIST * 0.01;
                this.vx -= dx * force;
                this.vy -= dy * force;
            }

            // Damping
            this.vx *= 0.999;
            this.vy *= 0.999;
        }

        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(56, 189, 248, ${this.opacity})`;
            ctx.fill();
        }
    }

    for (let i = 0; i < PARTICLE_COUNT; i++) {
        particles.push(new Particle());
    }

    function drawConnections() {
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < CONNECTION_DIST) {
                    const opacity = (1 - dist / CONNECTION_DIST) * 0.08;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(56, 189, 248, ${opacity})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }
    }

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        particles.forEach(p => {
            p.update();
            p.draw();
        });
        drawConnections();
        requestAnimationFrame(animate);
    }

    animate();
}

// ─── Stat Counter Animation ─────────────────────────────────────────────────────
function animateStatCounter() {
    // Load count from history
    fetch('/api/history')
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                emailCount = data.history.length;
                animateNumber('emailCounter', emailCount);
            }
        })
        .catch(() => { });
}

function animateNumber(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const duration = 1200;
    const start = performance.now();
    const startVal = parseInt(el.textContent) || 0;

    function tick(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const current = Math.round(startVal + (target - startVal) * eased);
        el.textContent = current;
        if (progress < 1) requestAnimationFrame(tick);
    }

    requestAnimationFrame(tick);
}

// ─── Toast Notifications ────────────────────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = {
        success: '✅',
        error: '❌',
        info: 'ℹ️',
        warning: '⚠️',
    };

    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${message}</span>
        <div class="toast-progress"></div>
    `;

    toast.style.position = 'relative';
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-out');
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ─── Trigger Button Selection ───────────────────────────────────────────────────
function initTriggerButtons() {
    const buttons = document.querySelectorAll('.trigger-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        });
    });
}

function getSelectedTrigger() {
    const active = document.querySelector('.trigger-btn.active');
    return active ? active.dataset.value : 'urgency';
}

// ─── Generate Email ─────────────────────────────────────────────────────────────
async function generateEmail() {
    const btn = document.getElementById('generateBtn');
    const overlay = document.getElementById('loadingOverlay');

    // Gather params
    const params = {
        emotional_trigger: getSelectedTrigger(),
        context: document.getElementById('context').value,
        attachment_type: document.getElementById('attachment_type').value,
        link_type: document.getElementById('link_type').value,
    };

    // Show loading
    btn.disabled = true;
    btn.classList.add('loading');
    overlay.style.display = 'flex';

    try {
        const response = await fetch('/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params),
        });

        const data = await response.json();

        if (data.success) {
            currentEmail = data.email;
            currentIndicators = data.indicators;
            currentParams = data.params;
            renderEmailPreview(data.email);
            renderIndicators(data.indicators);
            document.getElementById('exportBtn').disabled = false;
            document.getElementById('analyzeBtn').disabled = false;
            document.getElementById('sendBtn').disabled = false;
            loadHistory();

            // Update stat counter
            emailCount++;
            animateNumber('emailCounter', emailCount);

            showToast('Phishing email generated successfully!', 'success');
        } else {
            showToast('Error: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.classList.remove('loading');
        overlay.style.display = 'none';
    }
}

// ─── Render Email Preview ───────────────────────────────────────────────────────
function renderEmailPreview(email) {
    const placeholder = document.getElementById('emailPlaceholder');
    const preview = document.getElementById('emailPreview');
    const body = document.getElementById('emailBody');

    placeholder.style.display = 'none';
    preview.style.display = 'block';

    // Set header fields
    document.getElementById('emailFrom').textContent =
        `${email.sender_name} <${email.sender_email}>`;
    document.getElementById('emailSubject').textContent = email.subject;
    document.getElementById('emailDate').textContent = new Date().toLocaleString();

    // Set body with red-flag annotations
    let bodyHtml = email.body_html;

    // Wrap suspicious elements for red-flag highlighting
    if (currentParams) {
        // Annotate attachment references
        if (currentParams.attachment_filename) {
            const fname = currentParams.attachment_filename;
            bodyHtml = bodyHtml.replace(
                new RegExp(escapeRegex(fname), 'gi'),
                `<span data-red-flag="attachment" style="position: relative; cursor: help;">${fname}<span class="red-flag-tooltip">🚩 Suspicious Attachment — Check file extension!</span></span>`
            );
        }

        // Annotate suspicious links
        if (currentParams.suspicious_url) {
            bodyHtml = bodyHtml.replace(
                /(<a\s[^>]*href=["'][^"']*["'][^>]*>)(.*?)(<\/a>)/gi,
                (match, open, text, close) => {
                    return `<span data-red-flag="link" style="position: relative; cursor: help;">${open}${text}${close}<span class="red-flag-tooltip">🚩 Suspicious Link — Hover to check real URL!</span></span>`;
                }
            );
        }
    }

    // Annotate emotional trigger keywords
    if (currentIndicators) {
        const emotionalIndicator = currentIndicators.find(i => i.category === 'Emotional Manipulation');
        if (emotionalIndicator && emotionalIndicator.keywords) {
            emotionalIndicator.keywords.forEach(keyword => {
                const regex = new RegExp(`\\b(${escapeRegex(keyword)})\\b`, 'gi');
                bodyHtml = bodyHtml.replace(regex, (match) => {
                    return `<span data-red-flag="emotion" style="position: relative; cursor: help;">${match}<span class="red-flag-tooltip">🚩 Emotional Manipulation — ${emotionalIndicator.type}</span></span>`;
                });
            });
        }
    }

    body.innerHTML = bodyHtml;

    // Apply red-flag state
    if (redFlagsActive) {
        body.classList.add('red-flags-active');
    } else {
        body.classList.remove('red-flags-active');
    }

    // Scroll to preview on mobile
    if (window.innerWidth < 1100) {
        document.getElementById('emailContainer').scrollIntoView({
            behavior: 'smooth',
            block: 'start',
        });
    }
}

// ─── Toggle Red Flags ───────────────────────────────────────────────────────────
function toggleRedFlags() {
    const toggle = document.getElementById('redFlagToggle');
    const body = document.getElementById('emailBody');
    const analysisPanel = document.getElementById('analysisPanel');

    redFlagsActive = toggle.checked;

    if (redFlagsActive) {
        body.classList.add('red-flags-active');
        if (currentIndicators.length > 0) {
            analysisPanel.style.display = 'block';
            showToast('Red flag analysis enabled — hover over highlighted areas', 'warning');
        }
    } else {
        body.classList.remove('red-flags-active');
        analysisPanel.style.display = 'none';
    }
}

// ─── Render Indicators ──────────────────────────────────────────────────────────
function renderIndicators(indicators) {
    const list = document.getElementById('indicatorList');
    list.innerHTML = '';

    indicators.forEach(indicator => {
        const card = document.createElement('div');
        card.className = `indicator-card severity-${indicator.severity}`;

        let detailHtml = '';
        if (indicator.filename) {
            detailHtml = `<div class="indicator-detail">📎 ${indicator.filename}</div>`;
        } else if (indicator.url) {
            detailHtml = `<div class="indicator-detail">🔗 ${indicator.url}</div>`;
        } else if (indicator.keywords) {
            detailHtml = `<div class="indicator-detail">🔑 Keywords: ${indicator.keywords.join(', ')}</div>`;
        }

        card.innerHTML = `
            <div class="indicator-header">
                <span class="indicator-category">${indicator.category}</span>
                <span class="indicator-severity ${indicator.severity}">${indicator.severity}</span>
            </div>
            <div class="indicator-type">${indicator.type}</div>
            <div class="indicator-desc">${indicator.description}</div>
            ${detailHtml}
        `;

        list.appendChild(card);
    });
}

// ─── Load History ───────────────────────────────────────────────────────────────
async function loadHistory() {
    try {
        const response = await fetch('/api/history');
        const data = await response.json();

        const list = document.getElementById('historyList');

        if (!data.success || data.history.length === 0) {
            list.innerHTML = '<div class="empty-state"><div class="empty-icon">📨</div><p>No emails generated yet</p></div>';
            return;
        }

        list.innerHTML = '';
        data.history.forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.onclick = () => loadHistoryItem(item);

            const time = new Date(item.created_at).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
            });

            div.innerHTML = `
                <div class="history-subject">${item.subject || 'Untitled'}</div>
                <div class="history-meta">
                    <span class="history-tag">${item.emotional_trigger}</span>
                    <span class="history-tag">${item.context}</span>
                    <span>${time}</span>
                </div>
            `;
            list.appendChild(div);
        });
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

function loadHistoryItem(item) {
    currentEmail = {
        subject: item.subject,
        body_html: item.body_html,
        sender_name: item.sender_name,
        sender_email: item.sender_email,
    };
    currentIndicators = item.indicators || [];
    currentParams = {
        attachment_filename: item.attachment_filename,
        suspicious_url: item.suspicious_url,
    };
    currentEmailId = item.id;

    renderEmailPreview(currentEmail);
    renderIndicators(currentIndicators);
    document.getElementById('exportBtn').disabled = false;
    document.getElementById('analyzeBtn').disabled = false;
    document.getElementById('sendBtn').disabled = false;

    showToast('Loaded email from history', 'info', 2000);
}

// ─── Export ─────────────────────────────────────────────────────────────────────
function exportEmail() {
    if (!currentEmail) return;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${currentEmail.subject}</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 700px; margin: 40px auto; padding: 20px; background: #f8fafc; }
.email-card { background: #fff; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); overflow: hidden; }
.email-header { padding: 20px 24px; background: #f1f5f9; border-bottom: 1px solid #e2e8f0; }
.email-header strong { color: #334155; font-size: 13px; }
.email-header span { color: #64748b; font-size: 14px; }
.email-content { padding: 24px; }
.disclaimer { margin-top: 40px; padding: 16px; background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; text-align: center; font-size: 13px; color: #92400e; }
</style>
</head>
<body>
<div class="email-card">
<div class="email-header">
<strong>From:</strong> <span>${currentEmail.sender_name} &lt;${currentEmail.sender_email}&gt;</span><br>
<strong>Subject:</strong> <span>${currentEmail.subject}</span><br>
<strong>Date:</strong> <span>${new Date().toLocaleString()}</span>
</div>
<div class="email-content">
${currentEmail.body_html}
</div>
</div>
<div class="disclaimer">
⚠️ This is a simulated phishing email generated for security awareness training purposes only.<br>
Generated by PhishGuard AI
</div>
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing_email_${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);

    showToast('Email exported as HTML file', 'success', 3000);
}

// ─── Utilities ──────────────────────────────────────────────────────────────────
function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─── AI Provider Status Check ───────────────────────────────────────────────────
async function checkAIProvider() {
    try {
        const response = await fetch('/api/provider');
        const data = await response.json();
        const indicator = document.getElementById('aiStatusIndicator');
        const label = document.getElementById('aiStatusLabel');

        if (data.success) {
            // Remove old classes
            indicator.classList.remove('ai-active', 'ai-no-key', 'fallback');

            if (data.status === 'ai_active') {
                indicator.classList.add('ai-active');
                label.textContent = data.label;
            } else if (data.status === 'ai_no_key') {
                indicator.classList.add('ai-no-key');
                label.textContent = 'AI — No Key Set';
            } else {
                indicator.classList.add('fallback');
                label.textContent = 'Fallback Mode';
            }
        }
    } catch (err) {
        document.getElementById('aiStatusLabel').textContent = 'Engine Ready';
    }
}

// ─── AI Email Analyzer ──────────────────────────────────────────────────────────
async function analyzeEmail() {
    if (!currentEmail) {
        showToast('Generate an email first before analyzing', 'warning');
        return;
    }

    const analyzeBtn = document.getElementById('analyzeBtn');
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = '⏳ Analyzing...';

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                subject: currentEmail.subject,
                body_html: currentEmail.body_html,
                sender_email: currentEmail.sender_email,
            }),
        });

        const data = await response.json();

        if (data.success) {
            renderAIAnalysis(data.analysis, data.powered_by);
            showToast('AI threat analysis complete!', 'success');
        } else {
            showToast('Analysis error: ' + (data.error || 'Unknown'), 'error');
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = '🤖 AI Analyze';
    }
}

function renderAIAnalysis(analysis, poweredBy) {
    const panel = document.getElementById('aiAnalysisPanel');
    panel.style.display = 'block';

    // Set badge
    document.getElementById('aiPoweredBy').textContent = poweredBy;

    // Animate threat gauge
    const score = analysis.threat_score || 0;
    const circumference = 2 * Math.PI * 52; // r=52
    const fill = document.getElementById('gaugeFill');
    const number = document.getElementById('gaugeNumber');
    const level = document.getElementById('threatLevel');

    // Set color class
    fill.className = 'gauge-fill';
    if (score >= 80) fill.classList.add('threat-critical');
    else if (score >= 60) fill.classList.add('threat-high');
    else if (score >= 40) fill.classList.add('threat-medium');
    else fill.classList.add('threat-low');

    // Animate score
    const targetDash = (score / 100) * circumference;
    setTimeout(() => {
        fill.setAttribute('stroke-dasharray', `${targetDash} ${circumference}`);
    }, 100);
    animateNumber('gaugeNumber', score);

    // Set threat level
    level.textContent = analysis.threat_level || 'UNKNOWN';
    level.className = 'threat-level level-' + (analysis.threat_level || 'LOW');

    // Summary
    document.getElementById('aiSummary').textContent = analysis.summary || '';

    // Red Flags
    const flagsContainer = document.getElementById('aiRedFlags');
    flagsContainer.innerHTML = '<h4>🚩 Detected Red Flags</h4>';
    if (analysis.red_flags && analysis.red_flags.length > 0) {
        analysis.red_flags.forEach(flag => {
            const card = document.createElement('div');
            card.className = `ai-flag-card flag-${flag.severity || 'medium'}`;
            card.innerHTML = `
                <div class="ai-flag-name">${flag.flag}</div>
                <div class="ai-flag-desc">${flag.description}</div>
                <span class="ai-flag-severity sev-${flag.severity || 'medium'}">${flag.severity || 'medium'}</span>
            `;
            flagsContainer.appendChild(card);
        });
    }

    // Tactics
    const tacticsContainer = document.getElementById('aiTactics');
    if (analysis.social_engineering_tactics && analysis.social_engineering_tactics.length > 0) {
        tacticsContainer.innerHTML = '<h4>🧠 Social Engineering Tactics</h4>';
        const list = document.createElement('div');
        list.className = 'ai-tactics-list';
        analysis.social_engineering_tactics.forEach(tactic => {
            const badge = document.createElement('span');
            badge.className = 'ai-tactic-badge';
            badge.textContent = tactic;
            list.appendChild(badge);
        });
        tacticsContainer.appendChild(list);
    }

    // Recommendation
    const recContainer = document.getElementById('aiRecommendation');
    recContainer.innerHTML = `<strong>⚠️ Recommendation:</strong> ${analysis.recommendation || 'Report to IT security.'}`;

    // Scroll to AI analysis
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ─── Inbox Scanner ──────────────────────────────────────────────────────────────
async function scanInbox() {
    const emailAddr = document.getElementById('inboxEmail').value.trim();
    const password = document.getElementById('inboxPassword').value;
    const imapServer = document.getElementById('imapServer').value.trim();
    const count = parseInt(document.getElementById('scanCount').value);
    const scanBtn = document.getElementById('scanBtn');
    const resultsContainer = document.getElementById('scanResults');

    if (!emailAddr || !password) {
        showToast('Please enter your email and app password', 'warning');
        return;
    }

    // Show loading
    scanBtn.disabled = true;
    scanBtn.querySelector('.btn-text').textContent = 'Connecting & Scanning...';
    scanBtn.classList.add('loading');
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <div class="loading-spinner" style="margin: 0 auto 12px;"></div>
            <p>Connecting to inbox and analyzing ${count} emails with AI...<br>
            <small style="color: var(--text-muted)">This may take 30-60 seconds depending on email count</small></p>
        </div>
    `;

    try {
        const response = await fetch('/api/inbox/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: emailAddr,
                password: password,
                imap_server: imapServer || undefined,
                count: count,
            }),
        });

        const data = await response.json();

        if (data.success) {
            renderScanResults(data);
            showToast(`Scanned ${data.total} emails — ${data.summary.threats} threat(s) found`,
                data.summary.threats > 0 ? 'warning' : 'success');
        } else {
            resultsContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">❌</div>
                    <p style="color: #f87171;">${data.error}</p>
                </div>
            `;
            showToast('Scan failed: ' + data.error, 'error', 6000);
        }
    } catch (err) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">❌</div>
                <p>Network error: ${err.message}</p>
            </div>
        `;
        showToast('Network error: ' + err.message, 'error');
    } finally {
        scanBtn.disabled = false;
        scanBtn.querySelector('.btn-text').textContent = 'Scan Inbox with AI';
        scanBtn.classList.remove('loading');
    }
}

function renderScanResults(data) {
    // Show summary
    const summary = document.getElementById('scanSummary');
    summary.style.display = 'grid';
    document.getElementById('summSafe').textContent = data.summary.safe;
    document.getElementById('summSuspicious').textContent = data.summary.suspicious;
    document.getElementById('summThreats').textContent = data.summary.threats;
    document.getElementById('summTotal').textContent = data.total;

    // Render email cards
    const container = document.getElementById('scanResults');
    container.innerHTML = '';

    data.results.forEach((result, idx) => {
        const { email: em, analysis } = result;
        const verdict = analysis.verdict || 'SAFE';
        const score = analysis.threat_score || 0;

        const scoreClass = score >= 60 ? 'score-threat' : (score >= 30 ? 'score-suspicious' : 'score-safe');

        // Build red flags HTML
        let flagsHtml = '';
        if (analysis.red_flags && analysis.red_flags.length > 0) {
            flagsHtml = '<div class="scan-detail-flags">';
            analysis.red_flags.forEach(f => {
                flagsHtml += `
                    <div class="ai-flag-card flag-${f.severity || 'medium'}">
                        <div class="ai-flag-name">${f.flag}</div>
                        <div class="ai-flag-desc">${f.explanation || f.description || ''}</div>
                        <span class="ai-flag-severity sev-${f.severity || 'medium'}">${f.severity || 'medium'}</span>
                    </div>
                `;
            });
            flagsHtml += '</div>';
        }

        // Positive signals
        let positivesHtml = '';
        if (analysis.positive_signals && analysis.positive_signals.length > 0) {
            positivesHtml = '<div class="scan-detail-positives">';
            analysis.positive_signals.forEach(p => {
                positivesHtml += `<span class="scan-positive-badge">✅ ${p}</span>`;
            });
            positivesHtml += '</div>';
        }

        const card = document.createElement('div');
        card.className = `scan-email-card verdict-${verdict}`;
        card.onclick = () => card.classList.toggle('expanded');

        card.innerHTML = `
            <div class="scan-email-header">
                <div class="scan-email-info">
                    <div class="scan-email-subject">${em.subject || '(no subject)'}</div>
                    <div class="scan-email-sender">${em.sender_name} &lt;${em.sender_email}&gt;</div>
                </div>
                <span class="verdict-badge v-${verdict}">${verdict}</span>
            </div>
            <div class="scan-email-snippet">${em.snippet || ''}</div>
            <div class="scan-email-meta">
                <span>📊 Score: ${score}/100</span>
                <span>🎯 ${analysis.confidence || 0}% confidence</span>
                ${em.has_attachments ? '<span>📎 Attachments</span>' : ''}
                ${analysis.ai_powered ? '<span>🤖 AI</span>' : '<span>📐 Rules</span>'}
            </div>
            <div class="scan-score-bar">
                <div class="scan-score-fill ${scoreClass}" style="width: 0%;" data-target="${score}"></div>
            </div>
            <div class="scan-email-details">
                <div class="scan-detail-summary">${analysis.summary || ''}</div>
                ${flagsHtml}
                ${positivesHtml}
                <div class="ai-recommendation">
                    <strong>💡 Recommendation:</strong> ${analysis.recommendation || 'No specific recommendation.'}
                </div>
            </div>
        `;

        container.appendChild(card);

        // Animate score bar
        setTimeout(() => {
            const fill = card.querySelector('.scan-score-fill');
            if (fill) fill.style.width = `${score}%`;
        }, 100 + idx * 80);
    });
}

// ─── Send Email Modal ───────────────────────────────────────────────────────────
function openSendModal() {
    if (!currentEmail) {
        showToast('Generate an email first', 'warning');
        return;
    }
    document.getElementById('sendModal').style.display = 'flex';
    if (window.lucide) lucide.createIcons();
}

function closeSendModal() {
    document.getElementById('sendModal').style.display = 'none';
}

// Close modal on backdrop click
document.addEventListener('click', (e) => {
    if (e.target.id === 'sendModal') closeSendModal();
});

async function sendGeneratedEmail() {
    const senderEmail = document.getElementById('sendFromEmail').value.trim();
    const senderPassword = document.getElementById('sendFromPassword').value;
    const recipientEmail = document.getElementById('sendToEmail').value.trim();
    const displayName = document.getElementById('sendDisplayName').value.trim();
    const btn = document.getElementById('sendConfirmBtn');

    if (!senderEmail || !senderPassword) {
        showToast('Enter your email and app password', 'warning');
        return;
    }
    if (!recipientEmail) {
        showToast('Enter the recipient email', 'warning');
        return;
    }
    if (!currentEmail) {
        showToast('Generate an email first', 'warning');
        return;
    }

    btn.disabled = true;
    const btnText = btn.querySelector('.btn-text');
    btnText.textContent = 'Sending...';

    try {
        const response = await fetch('/api/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sender_email: senderEmail,
                sender_password: senderPassword,
                recipient_email: recipientEmail,
                subject: currentEmail.subject,
                body_html: currentEmail.body_html,
                display_name: displayName || currentEmail.sender_name,
            }),
        });

        const data = await response.json();

        if (data.success) {
            showToast(`Email sent to ${recipientEmail}! Scan your inbox to detect it.`, 'success', 6000);
            closeSendModal();
        } else {
            showToast('Send failed: ' + data.error, 'error', 6000);
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btnText.textContent = 'Send Email Now';
    }
}

// Re-initialize Lucide icons after dynamic renders
function refreshIcons() {
    if (window.lucide) lucide.createIcons();
}
