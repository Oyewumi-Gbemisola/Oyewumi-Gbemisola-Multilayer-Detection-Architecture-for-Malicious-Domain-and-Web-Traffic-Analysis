# ============================================================
# app.py — G-URLs 2.0 Flask Backend
# ============================================================
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import requests
import base64
from scoring import (
    get_dns_features,    calculate_dns_score,
    get_tls_features,    calculate_tls_score,
    get_network_features, calculate_network_score,
    get_url_features,    calculate_url_score,
    combined_score,      get_ml_predictions
)

app = Flask(__name__)

VT_API_KEY = "c87e9c848dd61198636e23d4fa12f5853da81361837f3f7578bddbdf6dfbe2a6"

def extract_domain(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain, url

def virustotal_scan(url):
    try:
        url_id = base64.urlsafe_b64encode(
            url.encode()).decode().strip('=')
        headers = {'x-apikey': VT_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10)

        if response.status_code == 200:
            data  = response.json()
            stats = data['data']['attributes'][
                    'last_analysis_stats']
            results = data['data']['attributes'][
                      'last_analysis_results']
            mal  = stats.get('malicious', 0)
            sus  = stats.get('suspicious', 0)
            har  = stats.get('harmless', 0)
            und  = stats.get('undetected', 0)
            total = mal + sus + har + und
            flagged = []
            for vendor, r in results.items():
                if r['category'] in [
                        'malicious', 'suspicious']:
                    flagged.append({
                        'vendor':   vendor,
                        'category': r['category'],
                        'result':   r.get('result', '')
                    })
            return {
                'success':    True,
                'malicious':  mal,
                'suspicious': sus,
                'harmless':   har,
                'undetected': und,
                'total':      total,
                'flagged_by': flagged[:10],
                'verdict':    ('MALICIOUS' if mal > 3
                               else 'SUSPICIOUS'
                               if mal > 0 else 'CLEAN'),
                'percentage': round(mal/total*100, 1)
                              if total > 0 else 0
            }
        elif response.status_code == 404:
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={'url': url}, timeout=10)
            return {
                'success': True, 'malicious': 0,
                'suspicious': 0, 'harmless': 0,
                'undetected': 0, 'total': 0,
                'flagged_by': [], 'verdict': 'NOT YET ANALYSED',
                'percentage': 0,
                'message': 'URL submitted for first-time analysis'
            }
        return {'success': False,
                'error': f'API error: {response.status_code}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyse', methods=['POST'])
def analyse():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    domain, full_url = extract_domain(url)

    # ── Module A: DNS ────────────────────────────────────────
    try:
        dns_feat   = get_dns_features(domain)
        dns_result = calculate_dns_score(dns_feat)
        dns_result['features'] = dns_feat
    except Exception as e:
        dns_feat   = {}
        dns_result = {
            'score': 0, 'max_score': 18,
            'verdict': 'ERROR',
            'rules_fired': [f'DNS lookup failed: {str(e)}'],
            'features': {}
        }

    # ── Module B: TLS ────────────────────────────────────────
    try:
        tls_feat   = get_tls_features(domain)
        tls_result = calculate_tls_score(tls_feat)
        tls_result['features'] = tls_feat
    except Exception as e:
        tls_feat   = {}
        tls_result = {
            'score': 0, 'max_score': 29,
            'verdict': 'ERROR',
            'rules_fired': [f'TLS check failed: {str(e)}'],
            'features': {}
        }

    # ── Module C: Network ────────────────────────────────────
    try:
        net_feat   = get_network_features(domain, full_url)
        net_result = calculate_network_score(net_feat)
        net_result['features'] = net_feat
    except Exception as e:
        net_feat   = {}
        net_result = {
            'score': 0, 'max_score': 29,
            'verdict': 'ERROR',
            'rules_fired': [f'Network check failed: {str(e)}'],
            'features': {}
        }

    # ── Module D: URL ────────────────────────────────────────
    try:
        url_feat   = get_url_features(full_url)
        url_result = calculate_url_score(url_feat)
        url_result['features'] = url_feat
    except Exception as e:
        url_feat   = {}
        url_result = {
            'score': 0, 'max_score': 29,
            'verdict': 'ERROR',
            'rules_fired': [f'URL analysis failed: {str(e)}'],
            'features': {}
        }

    # ── Combined Rule-Based ──────────────────────────────────
    combined = combined_score(
        dns_result, tls_result,
        net_result, url_result)

    # ── ML Predictions ───────────────────────────────────────
    ml_results = get_ml_predictions(
        dns_feat, tls_feat, net_feat, url_feat)

    # ── VirusTotal ───────────────────────────────────────────
    vt_result = virustotal_scan(full_url)

    return jsonify({
        'url':          full_url,
        'domain':       domain,
        'dns':          dns_result,
        'tls':          tls_result,
        'network':      net_result,
        'url_analysis': url_result,
        'combined':     combined,
        'ml':           ml_results,
        'virustotal':   vt_result
    })

if __name__ == '__main__':
    print("=" * 50)
    print("  G-URLs 2.0 — Starting...")
    print("  Open browser: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)