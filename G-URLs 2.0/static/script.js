// ============================================================
// G-URLs 2.0 — Frontend Logic
// ============================================================

function showPage(page, el) {
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
        p.classList.add('hidden');
    });
    document.querySelectorAll('.nav-link').forEach(l => {
        l.classList.remove('active');
    });
    const target = document.getElementById('page-' + page);
    if (target) {
        target.classList.add('active');
        target.classList.remove('hidden');
    }
    if (el) el.classList.add('active');
}

function setURL(url) {
    document.getElementById('url-input').value = url;
    document.getElementById('url-input').focus();
}

function handleKeyPress(e) {
    if (e.key === 'Enter') analyseURL();
}

function togglePanel(id) {
    const body    = document.getElementById(id);
    const toggleId = id.replace('-body', '-toggle');
    const icon    = document.getElementById(toggleId);
    if (body.classList.contains('hidden')) {
        body.classList.remove('hidden');
        if (icon) icon.style.transform = 'rotate(180deg)';
    } else {
        body.classList.add('hidden');
        if (icon) icon.style.transform = 'rotate(0deg)';
    }
}

async function analyseURL() {
    const urlInput = document.getElementById('url-input');
    const url      = urlInput.value.trim();
    if (!url) {
        urlInput.style.borderColor = '#e74c3c';
        setTimeout(() => {
            urlInput.style.borderColor = '';
        }, 1000);
        return;
    }

    document.getElementById('loading')
            .classList.remove('hidden');
    document.getElementById('results')
            .classList.add('hidden');
    animateSteps();

    try {
        const response = await fetch('/analyse', {
            method:  'POST',
            headers: {'Content-Type': 'application/json'},
            body:    JSON.stringify({url})
        });
        const data = await response.json();
        if (data.error) { showError(data.error); return; }
        document.getElementById('loading')
                .classList.add('hidden');
        document.getElementById('results')
                .classList.remove('hidden');
        displayResults(data);
        addToHistory(data);
    } catch (err) {
        showError('Analysis failed — check connection');
    }
}

function animateSteps() {
    const steps = ['step-dns', 'step-tls',
                   'step-network', 'step-url',
                   'step-ml', 'step-vt'];
    steps.forEach((id, i) => {
        const el = document.getElementById(id);
        if (el) {
            el.style.opacity = '0.3';
            setTimeout(() => {
                el.style.opacity  = '1';
                el.style.color    = '#4a9eff';
            }, i * 500);
        }
    });
}

function displayResults(data) {
    const combined = data.combined;

    // Verdict banner
    const title  = document.getElementById('verdict-title');
    const urlEl  = document.getElementById('verdict-url');
    const icon   = document.getElementById('verdict-icon');
    const banner = document.getElementById('verdict-banner');

    title.textContent = combined.verdict;
    urlEl.textContent = data.url || data.domain;
    banner.style.borderColor = getColor(combined.color);
    icon.className = 'verdict-icon ' +
        (combined.color === 'red'    ? 'high'   :
         combined.color === 'orange' ? 'medium' : 'low');
    icon.querySelector('i').className =
        combined.color === 'red'
            ? 'fas fa-skull-crossbones'
            : combined.color === 'orange'
            ? 'fas fa-exclamation-triangle'
            : 'fas fa-shield-alt';
    title.style.color = getColor(combined.color);

    // Gauge
    updateGauge(combined.percentage, combined.color);

    // Module cards
    displayModule('dns',     data.dns,          18);
    displayModule('tls',     data.tls,          29);
    displayModule('network', data.network,      29);
    displayModule('url',     data.url_analysis, 29);

    // Features panel
    displayFeatures(data);

    // ML panel
    if (data.ml) displayML(data.ml, combined);

    // VirusTotal
    displayVirusTotal(data.virustotal, combined, data.ml);
}

function updateGauge(pct, color) {
    const fill   = document.getElementById('gauge-fill');
    const number = document.getElementById('gauge-number');
    const max    = 251.2;
    const dash   = (pct / 100) * max;
    const hex    = getColor(color);
    fill.setAttribute('stroke-dasharray',
                       `${dash} ${max}`);
    fill.setAttribute('stroke', hex);
    number.textContent = pct + '%';
    number.style.fill  = hex;
}

function displayModule(id, result, maxScore) {
    if (!result) return;
    const scoreEl   = document.getElementById(id + '-score');
    const verdictEl = document.getElementById(id + '-verdict');
    const rulesEl   = document.getElementById(id + '-rules');
    const cardEl    = document.getElementById('card-' + id);
    if (!scoreEl) return;

    const score = result.score || 0;
    scoreEl.textContent = score;
    const pct = (score / maxScore) * 100;
    scoreEl.style.color =
        pct >= 60 ? '#e74c3c' :
        pct >= 30 ? '#e67e22' : '#27ae60';

    const verdict = result.verdict || 'LOW RISK';
    verdictEl.textContent = verdict;
    verdictEl.className   = 'module-verdict ' +
        (verdict.includes('HIGH')   ? 'high'   :
         verdict.includes('MEDIUM') ? 'medium' : 'low');

    rulesEl.innerHTML = '';
    const rules = result.rules_fired || [];
    if (rules.length === 0) {
        const item = document.createElement('div');
        item.className   = 'rule-item clean';
        item.textContent = '✓ No suspicious signals detected';
        rulesEl.appendChild(item);
    } else {
        rules.forEach(rule => {
            const item = document.createElement('div');
            const isInfo = rule.includes('(+0)');
            item.className   = isInfo
                ? 'rule-item info' : 'rule-item';
            item.textContent = (isInfo ? 'ℹ ' : '⚠ ') + rule;
            rulesEl.appendChild(item);
        });
    }

    if (cardEl) {
        cardEl.style.borderColor =
            verdict.includes('HIGH')
                ? 'rgba(231,76,60,0.4)'
                : verdict.includes('MEDIUM')
                ? 'rgba(230,126,34,0.4)'
                : 'rgba(39,174,96,0.2)';
    }
}

function displayFeatures(data) {
    const grid = document.getElementById('features-grid');
    grid.innerHTML = '';

    const sections = [
        {
            title: 'Module A — DNS Features',
            color: '#2980b9',
            data:  data.dns?.features || {},
            keys:  [
                'domain_entropy', 'domain_len',
                'ttl_a', 'ttl_ns', 'a_record_count',
                'ns_count', 'has_mx', 'has_txt',
                'has_soa', 'dnssec_configured',
                'domain_age_category',
                'days_until_expiry', 'ip_alive_ratio',
                'avg_rtt', 'tld_suspicious'
            ]
        },
        {
            title: 'Module B — TLS Features',
            color: '#8e44ad',
            data:  data.tls?.features || {},
            keys:  [
                'has_tls', 'tls_version_risk',
                'cert_chain_length', 'is_self_signed',
                'cert_validity_days', 'is_short_lived',
                'is_very_long_lived',
                'cert_expired_at_capture',
                'issuer_is_trusted',
                'issuer_is_letsencrypt',
                'has_wildcard_cert', 'has_ct_log',
                'low_extension_count'
            ]
        },
        {
            title: 'Module C — Network Features',
            color: '#d35400',
            data:  data.network?.features || {},
            keys:  [
                'responds_http', 'responds_https',
                'redirect_count', 'response_time_ms',
                'uses_port_80_only', 'Destination Port',
                'Flow Duration', 'Flow Bytes/s',
                'Average Packet Size'
            ]
        },
        {
            title: 'Module D — URL Features',
            color: '#16a085',
            data:  data.url_analysis?.features || {},
            keys:  [
                'URLLength', 'DomainLength',
                'IsDomainIP', 'URLSimilarityIndex',
                'IsHTTPS', 'DegitRatioInURL',
                'SpacialCharRatioInURL',
                'HasObfuscation', 'NoOfSubDomain',
                'NoOfEqualsInURL',
                'CharContinuationRate',
                'DomainTitleMatchScore'
            ]
        }
    ];

    sections.forEach(section => {
        const block = document.createElement('div');
        block.className = 'feature-block';
        block.style.borderLeft =
            `3px solid ${section.color}`;

        let html = `<div class="feature-block-title"
            style="color:${section.color}">
            ${section.title}</div>
            <div class="feature-rows">`;

        section.keys.forEach(key => {
            const val = section.data[key];
            if (val !== undefined && val !== null) {
                const display = typeof val === 'number'
                    ? (Number.isInteger(val)
                       ? val : val.toFixed(4))
                    : val;
                html += `<div class="feature-row">
                    <span class="feature-key">${key}</span>
                    <span class="feature-val">${display}</span>
                </div>`;
            }
        });

        html += '</div>';
        block.innerHTML = html;
        grid.appendChild(block);
    });
}

function displayML(ml, combined) {
    const moduleMap = [
        {rowId: 'ml-dns-row',  key: 'dns'},
        {rowId: 'ml-tls-row',  key: 'tls'},
        {rowId: 'ml-net-row',  key: 'network'},
        {rowId: 'ml-url-row',  key: 'url'},
    ];

    const modelLabels = [
        {key: 'lr',  label: 'Logistic\nRegression',
         note: 'academic'},
        {key: 'dt',  label: 'Decision\nTree',
         note: 'academic'},
        {key: 'rf',  label: 'Random\nForest',
         note: 'primary'},
        {key: 'xgb', label: 'XGBoost',
         note: 'primary'},
    ];

    moduleMap.forEach(({rowId, key}) => {
        const row = document.getElementById(rowId);
        if (!row) return;
        row.innerHTML = '';

        const moduleData = ml[key] || {};

        modelLabels.forEach(({key: mk, label, note}) => {
            const result = moduleData[mk];
            const card   = document.createElement('div');
            card.className = `ml-model-card ${
                note === 'academic'
                    ? 'academic-model' : 'primary-model'}`;

            if (!result || result.error) {
                card.innerHTML = `
                    <div class="ml-model-label">
                        ${label.replace('\n', '<br>')}
                    </div>
                    <div class="ml-model-prob grey">
                        N/A
                    </div>
                    <div class="ml-model-verdict grey">
                        ${note === 'academic'
                          ? 'Academic ref' : 'Error'}
                    </div>`;
            } else {
                const prob    = result.probability;
                const verdict = result.verdict;
                const color   = getColor(
                    verdict === 'HIGH RISK'   ? 'red'   :
                    verdict === 'MEDIUM RISK' ? 'orange':
                                                'green');
                card.innerHTML = `
                    <div class="ml-model-label">
                        ${label.replace('\n', '<br>')}
                        ${note === 'academic'
                          ? '<span class="acad-tag">'
                            + 'Phase 5</span>' : ''}
                    </div>
                    <div class="ml-model-prob"
                         style="color:${color}">
                        ${prob}%
                    </div>
                    <div class="ml-model-verdict"
                         style="color:${color}">
                        ${verdict}
                    </div>`;
            }
            row.appendChild(card);
        });
    });

    // RF combined
    const rfComb = ml.combined_rf || {};
    const rfV    = document.getElementById('ml-rf-verdict');
    const rfP    = document.getElementById('ml-rf-prob');
    if (rfV && rfComb.verdict) {
        rfV.textContent = rfComb.verdict;
        rfV.style.color = getColor(rfComb.color);
    }
    if (rfP && rfComb.probability !== undefined) {
        rfP.textContent = rfComb.probability + '% risk';
    }

    // XGBoost combined
    const xgbComb = ml.combined_xgb || {};
    const xgbV    = document.getElementById(
        'ml-xgb-verdict');
    const xgbP    = document.getElementById('ml-xgb-prob');
    if (xgbV && xgbComb.verdict) {
        xgbV.textContent = xgbComb.verdict;
        xgbV.style.color = getColor(xgbComb.color);
    }
    if (xgbP && xgbComb.probability !== undefined) {
        xgbP.textContent = xgbComb.probability + '% risk';
    }

    // Three-way comparison
    const compRules = document.getElementById('comp-rules');
    const compRF    = document.getElementById('comp-rf');
    const compXGB   = document.getElementById('comp-xgb');

    if (compRules) {
        compRules.textContent =
            combined.verdict.split('—')[0].trim();
        compRules.style.color = getColor(combined.color);
    }
    if (compRF && rfComb.verdict) {
        compRF.textContent =
            rfComb.verdict.split('—')[0].trim();
        compRF.style.color = getColor(rfComb.color);
    }
    if (compXGB && xgbComb.verdict) {
        compXGB.textContent =
            xgbComb.verdict.split('—')[0].trim();
        compXGB.style.color = getColor(xgbComb.color);
    }

    // Update three-way VT comparison
    const compMLVT = document.getElementById('comp-ml-vt');
    if (compMLVT && rfComb.verdict) {
        compMLVT.textContent =
            rfComb.verdict.split('—')[0].trim();
        compMLVT.style.color = getColor(rfComb.color);
    }
}

function displayVirusTotal(vt, combined, ml) {
    if (!vt) return;
    document.getElementById('vt-malicious')
            .textContent = vt.malicious  || 0;
    document.getElementById('vt-suspicious')
            .textContent = vt.suspicious || 0;
    document.getElementById('vt-harmless')
            .textContent = vt.harmless   || 0;
    document.getElementById('vt-undetected')
            .textContent = vt.undetected || 0;

    const vtv = document.getElementById('vt-verdict');
    vtv.textContent = vt.verdict || 'UNKNOWN';
    vtv.style.color =
        vt.verdict === 'MALICIOUS'  ? '#e74c3c' :
        vt.verdict === 'SUSPICIOUS' ? '#e67e22' :
        vt.verdict === 'CLEAN'      ? '#27ae60' : '#8892a4';

    const flagged = document.getElementById('vt-flagged');
    flagged.innerHTML = '';
    if (vt.flagged_by && vt.flagged_by.length > 0) {
        vt.flagged_by.forEach(v => {
            const tag = document.createElement('span');
            tag.className   = 'vt-flag-item';
            tag.textContent = v.vendor + ': ' + v.result;
            flagged.appendChild(tag);
        });
    } else if (vt.success) {
        flagged.innerHTML =
            '<span style="color:#27ae60;font-size:0.85rem">'
            + '✓ No vendors flagged this URL</span>';
    }

    // Three-way comparison
    const cg = document.getElementById('comp-gurls');
    const cv = document.getElementById('comp-vt');
    if (cg) {
        cg.textContent = combined.verdict
            .split('—')[0].trim();
        cg.style.color = getColor(combined.color);
    }
    if (cv) {
        cv.textContent = vt.verdict || 'UNKNOWN';
        cv.style.color =
            vt.verdict === 'MALICIOUS'  ? '#e74c3c' :
            vt.verdict === 'SUSPICIOUS' ? '#e67e22' :
            vt.verdict === 'CLEAN'      ? '#27ae60' :
                                          '#8892a4';
    }
}

function addToHistory(data) {
    const tbody = document.getElementById('history-body');
    const empty = tbody.querySelector('.history-empty');
    if (empty) empty.remove();

    const combined = data.combined;
    const ml       = data.ml;
    const vt       = data.virustotal;

    const vc = combined.color === 'red'    ? 'badge-high'   :
               combined.color === 'orange' ? 'badge-medium' :
                                             'badge-low';
    const mlVerdict = ml?.combined?.verdict
        ? ml.combined.verdict.split('—')[0].trim()
        : 'N/A';
    const mlColor = ml?.combined?.color
        ? getColor(ml.combined.color) : '#8892a4';

    const row = document.createElement('tr');
    row.innerHTML = `
        <td style="font-family:'JetBrains Mono',monospace;
            max-width:180px;overflow:hidden;
            text-overflow:ellipsis;white-space:nowrap"
            title="${data.url || data.domain}">
            ${(data.url || '').substring(0, 28)}...
        </td>
        <td>${data.dns?.score ?? '—'}/18</td>
        <td>${data.tls?.score ?? '—'}/29</td>
        <td>${data.network?.score ?? '—'}/29</td>
        <td>${data.url_analysis?.score ?? '—'}/29</td>
        <td>${combined.percentage}%</td>
        <td class="${vc}">
            ${combined.verdict.split('—')[0].trim()}
        </td>
        <td style="color:${mlColor};font-weight:700">
            ${mlVerdict}
        </td>
        <td>${vt?.success
            ? vt.malicious + '/' + vt.total + ' engines'
            : 'N/A'}</td>`;

    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 10) {
        tbody.removeChild(tbody.lastChild);
    }
}

function getColor(color) {
    return color === 'red'    ? '#e74c3c' :
           color === 'orange' ? '#e67e22' :
                                '#27ae60';
}

function showError(msg) {
    document.getElementById('loading')
            .classList.add('hidden');
    alert('Error: ' + msg);
}