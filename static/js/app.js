/**
 * PhishGuard AI — Frontend Logic
 * Handles email generation, preview rendering, red-flag highlighting, and history.
 */

// ─── State ──────────────────────────────────────────────────────────────────────
let currentEmail = null;
let currentIndicators = [];
let currentParams = null;
let currentEmailId = null;
let redFlagsActive = false;

// ─── DOM Ready ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initTriggerButtons();
    loadHistory();
});

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
            loadHistory();
        } else {
            alert('Error generating email: ' + (data.error || 'Unknown error'));
        }
    } catch (err) {
        alert('Network error: ' + err.message);
    } finally {
        btn.disabled = false;
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
            // Wrap <a> tags that contain the suspicious URL
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
                    // Don't annotate if already inside a data-red-flag span
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
            list.innerHTML = '<p class="empty-state">No emails generated yet</p>';
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
}

// ─── Export ─────────────────────────────────────────────────────────────────────
function exportEmail() {
    if (!currentEmail) return;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${currentEmail.subject}</title>
<style>body{font-family:'Segoe UI',Arial,sans-serif;max-width:700px;margin:40px auto;padding:20px;}</style>
</head>
<body>
<div style="background:#f5f5f5;padding:15px;border-radius:8px;margin-bottom:20px;">
<strong>From:</strong> ${currentEmail.sender_name} &lt;${currentEmail.sender_email}&gt;<br>
<strong>Subject:</strong> ${currentEmail.subject}<br>
<strong>Date:</strong> ${new Date().toLocaleString()}
</div>
${currentEmail.body_html}
<hr style="margin-top:40px;">
<p style="color:#999;font-size:12px;text-align:center;">
⚠️ This is a simulated phishing email generated for security awareness training purposes only.
Generated by PhishGuard AI.
</p>
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing_email_${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
}

// ─── Utilities ──────────────────────────────────────────────────────────────────
function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
