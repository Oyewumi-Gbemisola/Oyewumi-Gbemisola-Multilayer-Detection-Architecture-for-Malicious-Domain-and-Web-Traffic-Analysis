# ============================================================
# scoring.py — G-URLs 2.0 Detection Engine
# Scoring functions match exactly the research evaluation
# ============================================================
import re
import ssl
import socket
import math
import requests
import joblib
import numpy as np
import os
from datetime import datetime
from urllib.parse import urlparse

# ── Paths ────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# ── Constants ────────────────────────────────────────────────
CAPTURE_DATE = datetime(2024, 8, 1)

TRUSTED_ORGS = {
    "let's encrypt", "digicert inc", "sectigo limited",
    "globalsign", "comodo ca limited", "amazon",
    "google trust services", "unizeto technologies s.a.",
    "certum", "identrust", "godaddy.com, inc.",
    "entrust, inc.", "verisign", "internet security research group"
}

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top',
    'club', 'online', 'site', 'ru', 'cn', 'pw',
    'cc', 'info', 'biz'
}
DNS_FEATURES = [
    'domain_entropy', 'domain_len', 'ttl_a', 'ttl_ns',
    'ttl_soa', 'ttl_mx', 'ttl_very_low', 'ttl_zero_a',
    'a_record_count', 'ns_count', 'has_mx', 'has_txt',
    'soa_min_ttl', 'soa_refresh', 'soa_expire',
    'dnssec_configured', 'dnssec_selfsign_ok',
    'a_record_authoritative', 'domain_age_days',
    'days_until_expiry', 'days_since_modified',
    'status_flag_count', 'domain_age_category',
    'ip_alive_count', 'ip_total_count',
    'ip_alive_ratio', 'avg_rtt'
]

TLS_FEATURES = [
    'has_tls', 'tls_version_risk', 'cipher_is_weak',
    'cert_chain_length', 'is_self_signed',
    'cert_validity_days', 'is_short_lived',
    'is_very_long_lived', 'cert_expired_at_capture',
    'cert_not_yet_valid', 'issuer_is_trusted',
    'issuer_is_letsencrypt', 'extension_count',
    'low_extension_count', 'has_wildcard_cert',
    'has_ct_log'
]

NETWORK_FEATURES = [
    'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Average Packet Size', 'Flow Duration',
    'Flow IAT Mean', 'Flow IAT Std',
    'Flow Packets/s', 'Flow Bytes/s',
    'SYN Flag Count', 'FIN Flag Count',
    'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'Down/Up Ratio', 'Fwd Packets/s', 'Bwd Packets/s',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'Destination Port'
]

URL_FEATURES = [
    'URLLength', 'DomainLength', 'IsDomainIP',
    'URLSimilarityIndex', 'CharContinuationRate',
    'TLDLegitimateProb', 'NoOfSubDomain',
    'HasObfuscation', 'ObfuscationRatio',
    'LetterRatioInURL', 'DegitRatioInURL',
    'NoOfEqualsInURL', 'NoOfQMarkInURL',
    'NoOfAmpersandInURL', 'SpacialCharRatioInURL',
    'IsHTTPS', 'NoOfURLRedirect',
    'DomainTitleMatchScore', 'URLTitleMatchScore',
    'HasExternalFormSubmit', 'HasPasswordField',
    'Bank', 'Pay', 'Crypto',
    'HasHiddenFields', 'NoOfEmptyRef'
]

# ── Load ML models ───────────────────────────────────────────
def load_model(name):
    try:
        path = os.path.join(MODELS_DIR, name)
        if os.path.exists(path):
            return joblib.load(path)
    except Exception:
        pass
    return None

models = {
    # Tree-based — robust to feature scale differences
    'rf_dns':      load_model('rf_dns.pkl'),
    'rf_tls':      load_model('rf_tls.pkl'),
    'rf_network':  load_model('rf_network.pkl'),
    'rf_url':      load_model('rf_url.pkl'),
    'xgb_dns':     load_model('xgb_dns.pkl'),
    'xgb_tls':     load_model('xgb_tls.pkl'),
    'xgb_network': load_model('xgb_network.pkl'),
    'xgb_url':     load_model('xgb_url.pkl'),
    # Scale-dependent — shown for academic comparison only
    'lr_dns':      load_model('lr_dns.pkl'),
    'lr_tls':      load_model('lr_tls.pkl'),
    'lr_network':  load_model('lr_network.pkl'),
    'lr_url':      load_model('lr_url.pkl'),
    'dt_dns':      load_model('dt_dns.pkl'),
    'dt_tls':      load_model('dt_tls.pkl'),
    'dt_network':  load_model('dt_network.pkl'),
    'dt_url':      load_model('dt_url.pkl'),
    # Scalers for LR
    'scaler_dns':     load_model('scaler_dns.pkl'),
    'scaler_tls':     load_model('scaler_tls.pkl'),
    'scaler_network': load_model('scaler_network.pkl'),
    'scaler_url':     load_model('scaler_url.pkl'),
}

# ── Training data feature ranges for clamping ────────────────
# These ranges are derived from the actual dataset
# distributions to prevent out-of-range live features
FEATURE_RANGES = {
    'dns': {
        'domain_entropy':         (0, 4.5),
        'domain_len':             (3, 100),
        'ttl_a':                  (0, 86400),
        'ttl_ns':                 (0, 172800),
        'ttl_soa':                (0, 172800),
        'ttl_mx':                 (0, 86400),
        'ttl_very_low':           (0, 1),
        'ttl_zero_a':             (0, 1),
        'a_record_count':         (0, 20),
        'ns_count':               (0, 15),
        'has_mx':                 (0, 1),
        'has_txt':                (0, 1),
        'soa_min_ttl':            (0, 86400),
        'soa_refresh':            (0, 86400),
        'soa_expire':             (0, 2592000),
        'dnssec_configured':      (0, 1),
        'dnssec_selfsign_ok':     (0, 1),
        'a_record_authoritative': (0, 1),
        'domain_age_days':        (-1, 9000),
        'days_until_expiry':      (-365, 3650),
        'days_since_modified':    (0, 9000),
        'status_flag_count':      (0, 10),
        'domain_age_category':    (-1, 3),
        'ip_alive_count':         (0, 20),
        'ip_total_count':         (0, 20),
        'ip_alive_ratio':         (0, 1),
        'avg_rtt':                (0, 5000),
    },
    'tls': {
        'has_tls':                  (0, 1),
        'tls_version_risk':         (0, 3),
        'cipher_is_weak':           (0, 1),
        'cert_chain_length':        (0, 5),
        'is_self_signed':           (0, 1),
        'cert_validity_days':       (0, 3650),
        'is_short_lived':           (0, 1),
        'is_very_long_lived':       (0, 1),
        'cert_expired_at_capture':  (0, 1),
        'cert_not_yet_valid':       (0, 1),
        'issuer_is_trusted':        (0, 1),
        'issuer_is_letsencrypt':    (0, 1),
        'extension_count':          (0, 20),
        'low_extension_count':      (0, 1),
        'has_wildcard_cert':        (0, 1),
        'has_ct_log':               (0, 1),
    },
    'network': {
        'Total Fwd Packets':           (0, 500000),
        'Total Backward Packets':      (0, 500000),
        'Total Length of Fwd Packets': (0, 1e8),
        'Total Length of Bwd Packets': (0, 1e8),
        'Average Packet Size':         (0, 1500),
        'Flow Duration':               (0, 1.2e8),
        'Flow IAT Mean':               (0, 1.2e8),
        'Flow IAT Std':                (0, 1.2e8),
        'Flow Packets/s':              (0, 1e6),
        'Flow Bytes/s':                (0, 1e8),
        'SYN Flag Count':              (0, 500),
        'FIN Flag Count':              (0, 500),
        'RST Flag Count':              (0, 500),
        'PSH Flag Count':              (0, 500),
        'ACK Flag Count':              (0, 5000),
        'Down/Up Ratio':               (0, 100),
        'Fwd Packets/s':               (0, 1e6),
        'Bwd Packets/s':               (0, 1e6),
        'Init_Win_bytes_forward':      (-1, 65535),
        'Init_Win_bytes_backward':     (-1, 65535),
        'Destination Port':            (0, 65535),
    },
    'url': {
        'URLLength':             (0, 2000),
        'DomainLength':          (0, 200),
        'IsDomainIP':            (0, 1),
        'URLSimilarityIndex':    (0, 100),
        'CharContinuationRate':  (0, 1),
        'TLDLegitimateProb':     (0, 1),
        'NoOfSubDomain':         (0, 20),
        'HasObfuscation':        (0, 1),
        'ObfuscationRatio':      (0, 1),
        'LetterRatioInURL':      (0, 1),
        'DegitRatioInURL':       (0, 1),
        'NoOfEqualsInURL':       (0, 50),
        'NoOfQMarkInURL':        (0, 20),
        'NoOfAmpersandInURL':    (0, 20),
        'SpacialCharRatioInURL': (0, 1),
        'IsHTTPS':               (0, 1),
        'NoOfURLRedirect':       (0, 10),
        'DomainTitleMatchScore': (0, 100),
        'URLTitleMatchScore':    (0, 100),
        'HasExternalFormSubmit': (0, 1),
        'HasPasswordField':      (0, 1),
        'Bank':                  (0, 1),
        'Pay':                   (0, 1),
        'Crypto':                (0, 1),
        'HasHiddenFields':       (0, 1),
        'NoOfEmptyRef':          (0, 50),
    }
}

def clamp_features(features, module):
    """Clamp live feature values to training data ranges."""
    ranges  = FEATURE_RANGES.get(module, {})
    clamped = {}
    for key, val in features.items():
        if key in ranges:
            lo, hi = ranges[key]
            try:
                clamped[key] = float(
                    max(lo, min(hi, val or 0)))
            except Exception:
                clamped[key] = 0.0
        else:
            clamped[key] = val
    return clamped

def contextual_url_features(url_features):
    """
    For features that cannot be accurately computed
    live — DomainTitleMatchScore, URLTitleMatchScore,
    HasHiddenFields — use context-aware defaults
    based on available signals rather than fixed values.
    Documented limitation: these features require live
    page fetching which is outside scope of standalone
    web application deployment.
    """
    feats   = dict(url_features)
    is_https   = feats.get('IsHTTPS', 0)
    url_len    = feats.get('URLLength', 0)
    is_ip      = feats.get('IsDomainIP', 0)
    has_obf    = feats.get('HasObfuscation', 0)
    sim        = feats.get('URLSimilarityIndex', 50)
    digit_r    = feats.get('DegitRatioInURL', 0)
    special_r  = feats.get('SpacialCharRatioInURL', 0)
    subdomains = feats.get('NoOfSubDomain', 0)

    # Compute a cleanliness score from available signals
    clean_score = 0
    if is_https == 1:      clean_score += 2
    if url_len < 40:       clean_score += 2
    if is_ip == 0:         clean_score += 1
    if has_obf == 0:       clean_score += 1
    if sim >= 70:          clean_score += 2
    if digit_r < 0.05:     clean_score += 1
    if special_r < 0.05:   clean_score += 1
    if subdomains <= 1:    clean_score += 1

    # Map cleanliness to feature defaults
    if clean_score >= 8:
        # Very clean domain — high match scores
        feats['DomainTitleMatchScore'] = 85
        feats['URLTitleMatchScore']    = 85
        feats['HasHiddenFields']       = 1
        feats['HasExternalFormSubmit'] = 0
        feats['NoOfEmptyRef']          = 0
    elif clean_score >= 5:
        # Moderately clean
        feats['DomainTitleMatchScore'] = 55
        feats['URLTitleMatchScore']    = 55
        feats['HasHiddenFields']       = 0
        feats['HasExternalFormSubmit'] = 0
        feats['NoOfEmptyRef']          = 1
    else:
        # Suspicious signals — low match scores
        feats['DomainTitleMatchScore'] = 15
        feats['URLTitleMatchScore']    = 15
        feats['HasHiddenFields']       = 0
        feats['HasExternalFormSubmit'] = 1
        feats['NoOfEmptyRef']          = 3

    return feats

def contextual_tls_features(tls_features):
    """
    Adjust TLS features that differ between live
    certificate reading and Zenodo dataset extraction.
    cert_chain_length from live socket reads shorter
    chains than full PKIX chain enumeration in dataset.
    """
    feats = dict(tls_features)

    # If trusted issuer with CT log — likely has
    # proper chain even if socket read returns short
    if (feats.get('issuer_is_trusted', 0) == 1 and
            feats.get('has_ct_log', 0) == 1 and
            feats.get('is_self_signed', 0) == 0):
        feats['cert_chain_length'] = max(
            feats.get('cert_chain_length', 1), 2)
        feats['low_extension_count'] = 0
        feats['cipher_is_weak']      = 0

    return feats

def predict_module(model_key, features_dict,
                   feature_list, scaler_key=None):
    """
    Run a single model prediction with full error
    handling. Returns probability, prediction,
    verdict, and confidence flag.
    """
    try:
        model = models.get(model_key)
        if not model:
            return None

        import pandas as pd
        row = pd.DataFrame(
        [[features_dict.get(f, 0) for f in feature_list]],
        columns=feature_list
        )

        # Apply scaler if provided (LR only)
        if scaler_key:
            scaler = models.get(scaler_key)
            if scaler:
                row = scaler.transform(row)

        prob = float(model.predict_proba(row)[0][1])
        pred = int(model.predict(row)[0])

        verdict = ('HIGH RISK'   if prob >= 0.7 else
                   'MEDIUM RISK' if prob >= 0.4 else
                   'LOW RISK')

        return {
            'probability': round(prob * 100, 1),
            'prediction':  ('MALICIOUS' if pred == 1
                            else 'BENIGN'),
            'verdict':     verdict,
        }
    except Exception as e:
        return {'error': str(e)}


# ============================================================
# MODULE A — DNS Feature Extraction
# ============================================================
def get_dns_features(domain):
    import dns.resolver

    features = {
        'domain_entropy':        calculate_entropy(domain),
        'domain_len':            len(domain),
        'ttl_a':                 0,
        'ttl_ns':                0,
        'ttl_soa':               0,
        'ttl_mx':                0,
        'ttl_very_low':          0,
        'ttl_zero_a':            0,
        'a_record_count':        0,
        'ns_count':              0,
        'has_mx':                0,
        'has_txt':               0,
        'soa_min_ttl':           0,
        'soa_refresh':           0,
        'soa_expire':            0,
        'dnssec_configured':     0,
        'dnssec_selfsign_ok':    0,
        'a_record_authoritative':1,
        'domain_age_days':       -1,
        'days_until_expiry':     365,
        'days_since_modified':   999,
        'status_flag_count':     0,
        'domain_age_category':   -1,
        'ip_alive_count':        0,
        'ip_total_count':        0,
        'ip_alive_ratio':        1.0,
        'avg_rtt':               0,
        'tld_suspicious':        0,
        'has_soa':               0,
    }

    tld = domain.split('.')[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        features['tld_suspicious'] = 1

    try:
        ans = dns.resolver.resolve(domain, 'A')
        features['a_record_count'] = len(ans)
        features['ip_total_count'] = len(ans)
        if ans.rrset:
            ttl = ans.rrset.ttl
            features['ttl_a'] = ttl
            if ttl == 0:
                features['ttl_zero_a'] = 1
            elif ttl < 300:
                features['ttl_very_low'] = 1
        features['ip_alive_ratio'] = 1.0
        features['ip_alive_count'] = len(ans)
    except Exception:
        pass

    try:
        ans = dns.resolver.resolve(domain, 'NS')
        features['ns_count'] = len(ans)
        if ans.rrset:
            features['ttl_ns'] = ans.rrset.ttl
    except Exception:
        pass

    try:
        ans = dns.resolver.resolve(domain, 'MX')
        features['has_mx'] = 1
        if ans.rrset:
            features['ttl_mx'] = ans.rrset.ttl
    except Exception:
        features['has_mx'] = 0

    try:
        ans = dns.resolver.resolve(domain, 'TXT')
        features['has_txt'] = 1
    except Exception:
        features['has_txt'] = 0

    try:
        ans = dns.resolver.resolve(domain, 'SOA')
        features['has_soa'] = 1
        if ans.rrset:
            features['ttl_soa'] = ans.rrset.ttl
            soa = ans[0]
            features['soa_min_ttl'] = int(soa.minimum)
            features['soa_refresh'] = int(soa.refresh)
            features['soa_expire']  = int(soa.expire)
    except Exception:
        features['has_soa'] = 0

    return features

# ============================================================
# MODULE A — DNS Scoring (exact research rules)
# ============================================================
def calculate_dns_score(row):
    score = 0
    fired = []

    ttl = row.get('ttl_a', 0)
    if 0 < ttl < 300:
        score += 3
        fired.append(f'R11: Very low TTL ({ttl}s) — fast-flux suspected (+3)')
    elif ttl == 0:
        fired.append('R12: Zero TTL — data unavailable (+0)')

    if row.get('has_mx', 1) == 0:
        score += 2
        fired.append('R13: No MX record (+2)')

    if row.get('has_txt', 1) == 0:
        score += 1
        fired.append('R14: No TXT record (+1)')

    if row.get('has_soa', 1) == 0:
        score += 1
        fired.append('R15: No SOA record (+1)')

    ns = row.get('ns_count', 0)
    if ns == 2:
        score += 1
        fired.append('R16: Exactly 2 nameservers (+1)')
    elif ns > 6:
        score += 2
        fired.append(f'R17: {ns} nameservers — fast-flux (+2)')

    if row.get('a_record_count', 0) > 5:
        score += 2
        fired.append('R18: Many A records — fast-flux IP pool (+2)')

    age_cat = row.get('domain_age_category', 2)
    if age_cat == 0:
        score += 3
        fired.append('R19: Domain under 30 days old (+3)')
    elif age_cat == 1:
        score += 1
        fired.append('R20: Domain under 1 year old (+1)')
    elif age_cat == -1:
        fired.append('R21: Unknown domain age — noted (+0)')

    expiry = row.get('days_until_expiry', 365)
    if -30 <= expiry <= 30:
        score += 1
        fired.append(f'R22: Expiring in {expiry} days (+1)')

    modified = row.get('days_since_modified', 999)
    if 0 < modified < 7:
        score += 1
        fired.append('R23: Modified in last 7 days (+1)')

    if row.get('dnssec_configured', 1) == 0:
        fired.append('R24: No DNSSEC — noted (+0)')

    alive_ratio = row.get('ip_alive_ratio', 1.0)
    ip_total    = row.get('ip_total_count', 0)
    if ip_total > 0 and alive_ratio < 0.5:
        score += 2
        fired.append(f'R25: {alive_ratio:.0%} IPs alive — evasive (+2)')

    if row.get('avg_rtt', 1) == 0 and ip_total > 0:
        score += 1
        fired.append('R26: Zero avg RTT with IPs present (+1)')

    if row.get('status_flag_count', 0) > 2:
        score += 1
        fired.append('R27: Multiple status flags (+1)')

    if row.get('a_record_authoritative', 1) == 0:
        fired.append('R28: Non-authoritative resolution — noted (+0)')

    if score >= 8:
        verdict = 'HIGH RISK'
    elif score >= 4:
        verdict = 'MEDIUM RISK'
    else:
        verdict = 'LOW RISK'

    return {
        'score':       score,
        'max_score':   18,
        'verdict':     verdict,
        'rules_fired': fired
    }

# ============================================================
# MODULE B — TLS Feature Extraction
# ============================================================
def get_tls_features(domain):
    features = {
        'has_tls':               0,
        'tls_version_risk':      0,
        'cipher_is_weak':        0,
        'cert_chain_length':     0,
        'is_self_signed':        0,
        'cert_validity_days':    0,
        'is_short_lived':        0,
        'is_very_long_lived':    0,
        'cert_expired_at_capture': 0,
        'cert_not_yet_valid':    0,
        'issuer_is_trusted':     0,
        'issuer_is_letsencrypt': 0,
        'extension_count':       0,
        'low_extension_count':   0,
        'has_wildcard_cert':     0,
        'has_ct_log':            0,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection(
                (domain, 443), timeout=5) as sock:
            with context.wrap_socket(
                    sock, server_hostname=domain) as ssock:
                features['has_tls'] = 1
                cert    = ssock.getpeercert()
                version = ssock.version()

                if version == 'TLSv1.3':
                    features['tls_version_risk'] = 0
                elif version == 'TLSv1.2':
                    features['tls_version_risk'] = 1
                else:
                    features['tls_version_risk'] = 3

                issuer_dict = {}
                for field in cert.get('issuer', []):
                    for key, val in field:
                        issuer_dict[key] = val

                subject_dict = {}
                for field in cert.get('subject', []):
                    for key, val in field:
                        subject_dict[key] = val

                org = issuer_dict.get(
                    'organizationName', '').lower().strip()
                features['issuer_is_trusted'] = (
                    1 if any(t in org for t in TRUSTED_ORGS)
                    else 0)
                features['issuer_is_letsencrypt'] = (
                    1 if "let's encrypt" in org else 0)
                features['is_self_signed'] = (
                    1 if subject_dict == issuer_dict else 0)

                not_before = datetime.strptime(
                    cert['notBefore'],
                    '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(
                    cert['notAfter'],
                    '%b %d %H:%M:%S %Y %Z')
                valid_days = (not_after - not_before).days
                features['cert_validity_days'] = valid_days
                features['is_short_lived'] = (
                    1 if 0 < valid_days < 90 else 0)
                features['is_very_long_lived'] = (
                    1 if valid_days > 825 else 0)
                features['cert_expired_at_capture'] = (
                    1 if not_after < datetime.now() else 0)
                features['cert_not_yet_valid'] = (
                    1 if not_before > datetime.now() else 0)

                san = cert.get('subjectAltName', [])
                for _, v in san:
                    if v.startswith('*.'):
                        features['has_wildcard_cert'] = 1
                        break

                ext_count = len(cert.get('subjectAltName', []))
                features['extension_count'] = ext_count
                features['low_extension_count'] = (
                    1 if ext_count < 4 else 0)

                if features['issuer_is_trusted'] == 1:
                    features['has_ct_log'] = 1

                features['cert_chain_length'] = (
                    len(cert.get('subject', [])))

    except ssl.SSLCertVerificationError:
        features['has_tls'] = 1
        features['is_self_signed'] = 1
    except Exception:
        features['has_tls'] = 0

    return features

# ============================================================
# MODULE B — TLS Scoring (exact research rules)
# ============================================================
def calculate_tls_score(row):
    score = 0
    fired = []

    has_tls    = int(row.get('has_tls', 0))
    is_trusted = int(row.get('issuer_is_trusted', 0))
    is_self    = int(row.get('is_self_signed', 0))

    if has_tls == 0:
        score += 4
        fired.append('R1: No TLS present — bare infrastructure (+4)')

    if has_tls == 1 and is_trusted == 0:
        score += 4
        fired.append('R2: Untrusted certificate issuer — unknown CA (+4)')

    if has_tls == 1 and int(row.get('has_ct_log', 0)) == 0:
        score += 4
        fired.append('R3: No CT log entry — evasion of public monitoring (+4)')

    if int(row.get('is_short_lived', 0)) == 1:
        score += 3
        fired.append('R4: Short-lived certificate — rapid rotation suspected (+3)')

    if int(row.get('has_wildcard_cert', 0)) == 1:
        score += 3
        fired.append('R5: Wildcard certificate — subdomain campaign infrastructure (+3)')

    chain = int(row.get('cert_chain_length', 0))
    if has_tls == 1 and chain <= 1:
        score += 3
        fired.append('R6: Certificate chain length <= 1 — minimal PKI investment (+3)')

    if int(row.get('low_extension_count', 0)) == 1:
        score += 2
        fired.append('R7: Low certificate extension count — poorly configured cert (+2)')

    if is_self == 1:
        score += 2
        fired.append('R8: Self-signed certificate — bypasses CA validation (+2)')

    if int(row.get('is_very_long_lived', 0)) == 1:
        score += 2
        fired.append('R9: Very long-lived certificate — non-compliant CA (+2)')

    if int(row.get('cert_expired_at_capture', 0)) == 1 \
            and is_self == 1:
        score += 2
        fired.append('R10: Expired self-signed cert — throwaway infrastructure (+2)')

    if score >= 10:
        verdict = 'HIGH RISK'
    elif score >= 5:
        verdict = 'MEDIUM RISK'
    else:
        verdict = 'LOW RISK'

    return {
        'score':       score,
        'max_score':   29,
        'verdict':     verdict,
        'rules_fired': fired
    }

# ============================================================
# MODULE C — Network Feature Extraction
# ============================================================
def get_network_features(domain, url):
    features = {
        'Total Fwd Packets':        0,
        'Total Backward Packets':   0,
        'Total Length of Fwd Packets': 0,
        'Total Length of Bwd Packets': 0,
        'Average Packet Size':      0,
        'Flow Duration':            0,
        'Flow IAT Mean':            0,
        'Flow IAT Std':             0,
        'Flow Packets/s':           0,
        'Flow Bytes/s':             0,
        'SYN Flag Count':           0,
        'FIN Flag Count':           0,
        'RST Flag Count':           0,
        'PSH Flag Count':           0,
        'ACK Flag Count':           0,
        'Down/Up Ratio':            1,
        'Fwd Packets/s':            0,
        'Bwd Packets/s':            0,
        'Init_Win_bytes_forward':   0,
        'Init_Win_bytes_backward':  0,
        'Destination Port':         80,
        'responds_http':            0,
        'responds_https':           0,
        'redirect_count':           0,
        'response_time_ms':         9999,
        'uses_port_80_only':        0,
    }

    parsed = urlparse(url)
    port   = 443 if url.startswith('https') else 80
    features['Destination Port'] = port

    try:
        import time
        start = time.time()
        r = requests.get(
            f"http://{domain}",
            timeout=5,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'})
        elapsed = (time.time() - start) * 1000
        features['responds_http']    = 1
        features['response_time_ms'] = elapsed
        features['redirect_count']   = len(r.history)
        features['Flow Duration']    = int(elapsed * 1000)
        features['Flow Bytes/s']     = (
            len(r.content) / (elapsed/1000)
            if elapsed > 0 else 0)
        features['Total Fwd Packets'] = 1
        features['Average Packet Size'] = len(r.content)
    except Exception:
        features['responds_http'] = 0

    try:
        requests.get(
            f"https://{domain}",
            timeout=5, verify=False,
            headers={'User-Agent': 'Mozilla/5.0'})
        features['responds_https'] = 1
    except Exception:
        features['responds_https'] = 0

    if (features['responds_http'] == 1 and
            features['responds_https'] == 0):
        features['uses_port_80_only'] = 1

    return features

# ============================================================
# MODULE C — Network Scoring (exact research rules)
# ============================================================
def calculate_network_score(row):
    score = 0
    fired = []

    avg_pkt = row.get('Average Packet Size', 0)
    if avg_pkt < 50:
        score += 5
        fired.append('R1: Tiny average packet size — DoS/flood pattern (+5)')
    elif avg_pkt < 100:
        score += 2
        fired.append('R1b: Small average packet size — scanning pattern (+2)')

    fin = row.get('FIN Flag Count', 0)
    if fin > 0.5:
        score += 4
        fired.append('R2: High FIN flag count — aggressive connection cycling (+4)')
    elif fin > 0.1:
        score += 2
        fired.append('R2b: Elevated FIN flag count — abnormal termination (+2)')

    duration = row.get('Flow Duration', 0)
    if duration > 5000000:
        score += 4
        fired.append('R3: Very long flow duration — DoS/C2 persistence (+4)')
    elif duration > 1000000:
        score += 2
        fired.append('R3b: Long flow duration — sustained connection (+2)')

    flow_bps = row.get('Flow Bytes/s', 9999)
    if 0 < flow_bps < 100:
        score += 4
        fired.append('R4: Very low flow bytes/s — slowloris/stealthy attack (+4)')
    elif 0 < flow_bps < 500:
        score += 2
        fired.append('R4b: Low flow bytes/s — abnormal transfer rate (+2)')

    psh = row.get('PSH Flag Count', 0)
    if psh > 0.5:
        score += 3
        fired.append('R5: High PSH flag count — aggressive data push (+3)')

    dport = row.get('Destination Port', 0)
    syn   = row.get('SYN Flag Count', 0)
    if dport == 80 and syn == 0:
        score += 3
        fired.append('R6: HTTP port 80 with no SYN — established attack flow (+3)')

    suspicious_ports = {21, 22, 23, 445, 139, 3389, 8080}
    if dport in suspicious_ports:
        score += 2
        fired.append(f'R7: Suspicious destination port {dport} (+2)')

    bwd_win = row.get('Init_Win_bytes_backward', 1)
    if bwd_win == 0:
        score += 2
        fired.append('R8: Zero backward window — server not responding (+2)')

    pps = row.get('Flow Packets/s', 0)
    if pps > 10000:
        score += 2
        fired.append('R9: Very high packet rate — flood attack (+2)')

    if row.get('uses_port_80_only', 0) == 1:
        score += 3
        fired.append('R10: HTTP only — no HTTPS available (+3)')

    if score >= 10:
        verdict = 'HIGH RISK'
    elif score >= 5:
        verdict = 'MEDIUM RISK'
    else:
        verdict = 'LOW RISK'

    return {
        'score':       score,
        'max_score':   29,
        'verdict':     verdict,
        'rules_fired': fired
    }

# ============================================================
# MODULE D — URL Feature Extraction
# ============================================================
def get_url_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    if domain.startswith('www.'):
        domain = domain[4:]
    full_url = url.lower()

    suspicious_keywords = [
        'login', 'verify', 'secure', 'account',
        'update', 'confirm', 'banking', 'signin',
        'password', 'credential', 'suspend', 'validate'
    ]

    # Start with high similarity for clean domains
    sim = 100

    # Only penalise for genuinely suspicious patterns
    for kw in suspicious_keywords:
        if kw in full_url:
            sim -= 15

    is_ip = 1 if re.match(
        r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0
    if is_ip:
        sim -= 40

    subdomain_count = max(len(domain.split('.')) - 2, 0)
    if subdomain_count > 3:
        sim -= 20

    if '%' in url:
        sim -= 25

    # Clean short domains get high similarity
    if len(domain) < 20 and '.' in domain and not is_ip:
        sim = max(sim, 75)

    sim = max(0, min(100, sim))

    tld_prob = 0.522907
    tld = domain.split('.')[-1].lower() \
        if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        tld_prob = 0.005977

    features = {
        'URLLength':            len(url),
        'DomainLength':         len(domain),
        'IsDomainIP':           is_ip,
        'URLSimilarityIndex':   sim,
        'CharContinuationRate': calculate_continuation(url),
        'TLDLegitimateProb':    tld_prob,
        'NoOfSubDomain':        subdomain_count,
        'HasObfuscation':       1 if '%' in url else 0,
        'ObfuscationRatio':     url.count('%') / len(url)
                                if len(url) > 0 else 0,
        'LetterRatioInURL':     sum(c.isalpha()
                                    for c in url) / len(url)
                                if len(url) > 0 else 0,
        'DegitRatioInURL':      sum(c.isdigit()
                                    for c in url) / len(url)
                                if len(url) > 0 else 0,
        'NoOfEqualsInURL':      url.count('='),
        'NoOfQMarkInURL':       url.count('?'),
        'NoOfAmpersandInURL':   url.count('&'),
        'SpacialCharRatioInURL': sum(
            c in '@$!#%^&*()' for c in url) / len(url)
            if len(url) > 0 else 0,
        'IsHTTPS':              1 if url.startswith(
                                    'https') else 0,
        'NoOfURLRedirect':      max(url.count('//') - 1, 0),
        'DomainTitleMatchScore': sim,
        'URLTitleMatchScore':   sim,
        'HasExternalFormSubmit': 0,
        'HasPasswordField':     1 if 'password' in
                                full_url else 0,
        'Bank':     1 if any(w in full_url for w in
                    ['bank', 'banking', 'barclays',
                     'hsbc', 'lloyds', 'natwest']) else 0,
        'Pay':      1 if any(w in full_url for w in
                    ['pay', 'paypal', 'payment',
                     'checkout']) else 0,
        'Crypto':   1 if any(w in full_url for w in
                    ['crypto', 'bitcoin', 'wallet',
                     'ethereum']) else 0,
        'HasHiddenFields': 0,
        'NoOfEmptyRef':    0,
    }

    return features

# ============================================================
# MODULE D — URL Scoring (exact research rules)
# ============================================================
def calculate_url_score(row):
    score = 0
    fired = []

    similarity = row.get('URLSimilarityIndex', 100)
    if similarity < 30:
        score += 5
        fired.append('R1: Very low URL similarity — strong impersonation signal (+5)')
    elif similarity < 70:
        score += 3
        fired.append('R1b: Low URL similarity — possible impersonation (+3)')

    if row.get('IsHTTPS', 1) == 0:
        score += 4
        fired.append('R2: No HTTPS — unencrypted or untrusted connection (+4)')

    url_len = row.get('URLLength', 0)
    if url_len > 75:
        score += 4
        fired.append('R3: Very long URL — obfuscation or impersonation (+4)')
    elif url_len > 45:
        score += 2
        fired.append('R3b: Long URL — above normal length (+2)')

    title_match = row.get('DomainTitleMatchScore', 100)
    if title_match < 10:
        score += 4
        fired.append('R4: Very low domain-title match — content mismatch (+4)')
    elif title_match < 40:
        score += 2
        fired.append('R4b: Low domain-title match — partial mismatch (+2)')

    if row.get('DegitRatioInURL', 0) > 0.1:
        score += 3
        fired.append('R5: High digit ratio in URL — obfuscation pattern (+3)')

    if row.get('IsDomainIP', 0) == 1:
        score += 3
        fired.append('R6: IP address in URL — bypasses domain reputation (+3)')

    if row.get('SpacialCharRatioInURL', 0) > 0.1:
        score += 2
        fired.append('R7: High special character ratio — suspicious URL structure (+2)')

    if row.get('HasObfuscation', 0) == 1:
        score += 2
        fired.append('R8: URL obfuscation detected — deliberate concealment (+2)')

    if row.get('NoOfEqualsInURL', 0) > 2:
        score += 2
        fired.append('R9: Many query parameters — data harvesting pattern (+2)')

    char_cont = row.get('CharContinuationRate', 1)
    if char_cont < 0.5:
        score += 2
        fired.append('R10: Low character continuation — random/DGA-like domain (+2)')

    if (row.get('HasHiddenFields', 1) == 0 and
            row.get('IsHTTPS', 1) == 0):
        score += 2
        fired.append('R11: No hidden fields + no HTTPS — minimal phishing page (+2)')

    if score >= 10:
        verdict = 'HIGH RISK'
    elif score >= 5:
        verdict = 'MEDIUM RISK'
    else:
        verdict = 'LOW RISK'

    return {
        'score':       score,
        'max_score':   29,
        'verdict':     verdict,
        'rules_fired': fired
    }

# ============================================================
# ML PREDICTIONS
# ============================================================
def get_ml_predictions(dns_features, tls_features,
                        net_features, url_features):
    """
    Run all four ML models on live-extracted features.

    Tree-based models (RF, XGBoost) — used for primary
    live prediction. Robust to feature scale differences
    because they split on thresholds not distances.

    Scale-dependent models (LR, DT) — shown for academic
    Phase 5 comparison. LR uses StandardScaler to match
    training distribution. Results flagged as academic
    comparison rather than primary live prediction.

    Feature normalisation applied:
    - All features clamped to training data ranges
    - Context-aware defaults for uncomputable live
      features (DomainTitleMatchScore, HasHiddenFields)
    - TLS chain length adjusted for socket read
      vs full PKIX chain enumeration difference
    """

    # ── Prepare normalised feature sets ─────────────────────
    dns_norm = clamp_features(dns_features, 'dns')
    tls_norm = clamp_features(
        contextual_tls_features(tls_features), 'tls')
    net_norm = clamp_features(net_features, 'network')
    url_norm = clamp_features(
        contextual_url_features(url_features), 'url')

    results = {}

    # ── DNS — all four models ────────────────────────────────
    results['dns'] = {
        'lr':  predict_module('lr_dns',  dns_norm,
                              DNS_FEATURES,
                              'scaler_dns'),
        'dt':  predict_module('dt_dns',  dns_norm,
                              DNS_FEATURES),
        'rf':  predict_module('rf_dns',  dns_norm,
                              DNS_FEATURES),
        'xgb': predict_module('xgb_dns', dns_norm,
                              DNS_FEATURES),
    }

    # ── TLS — all four models ────────────────────────────────
    results['tls'] = {
        'lr':  predict_module('lr_tls',  tls_norm,
                              TLS_FEATURES,
                              'scaler_tls'),
        'dt':  predict_module('dt_tls',  tls_norm,
                              TLS_FEATURES),
        'rf':  predict_module('rf_tls',  tls_norm,
                              TLS_FEATURES),
        'xgb': predict_module('xgb_tls', tls_norm,
                              TLS_FEATURES),
    }

    # ── Network — all four models ────────────────────────────
    results['network'] = {
        'lr':  predict_module('lr_network',  net_norm,
                              NETWORK_FEATURES,
                              'scaler_network'),
        'dt':  predict_module('dt_network',  net_norm,
                              NETWORK_FEATURES),
        'rf':  predict_module('rf_network',  net_norm,
                              NETWORK_FEATURES),
        'xgb': predict_module('xgb_network', net_norm,
                              NETWORK_FEATURES),
    }

    # ── URL — all four models ────────────────────────────────
    results['url'] = {
        'lr':  predict_module('lr_url',  url_norm,
                              URL_FEATURES,
                              'scaler_url'),
        'dt':  predict_module('dt_url',  url_norm,
                              URL_FEATURES),
        'rf':  predict_module('rf_url',  url_norm,
                              URL_FEATURES),
        'xgb': predict_module('xgb_url', url_norm,
                              URL_FEATURES),
    }

    # ── Combined verdict — RF and XGBoost only ───────────────
    # LR and DT excluded from combined live verdict
    # due to feature distribution limitations
    W = {'dns': 0.2419, 'tls': 0.1257,
         'network': 0.2899, 'url': 0.3424}

    for primary_model in ['rf', 'xgb']:
        combined_score = 0.0
        valid = 0
        for module, w in W.items():
            m_result = results[module].get(primary_model)
            if m_result and 'probability' in m_result:
                combined_score += (
                    m_result['probability'] / 100) * w
                valid += 1
        if valid == 4:
            verdict = (
                'HIGH RISK — MALICIOUS'
                if combined_score >= 0.6 else
                'MEDIUM RISK — SUSPICIOUS'
                if combined_score >= 0.35 else
                'LOW RISK — LIKELY BENIGN')
            color = ('red'    if combined_score >= 0.6
                     else 'orange'
                     if combined_score >= 0.35
                     else 'green')
            results[f'combined_{primary_model}'] = {
                'probability': round(
                    combined_score * 100, 1),
                'verdict':     verdict,
                'color':       color,
            }

    # Primary combined verdict uses RF
    # (most stable on live features)
    results['combined'] = results.get(
        'combined_rf',
        results.get('combined_xgb', {
            'probability': 0,
            'verdict': 'UNABLE TO PREDICT',
            'color': 'grey'
        }))

    results['combined_rf']  = results.get('combined_rf',  {})
    results['combined_xgb'] = results.get('combined_xgb', {})

    return results

# ============================================================
# COMBINED RULE-BASED SCORING
# ============================================================
def combined_score(dns_result, tls_result,
                   net_result, url_result):
    DNS_MAX = 18
    TLS_MAX = 29
    NET_MAX = 29
    URL_MAX = 29

    W_DNS     = 0.2419
    W_TLS     = 0.1257
    W_NETWORK = 0.2899
    W_URL     = 0.3424

    dns_norm = min(dns_result['score'] / DNS_MAX, 1.0)
    tls_norm = min(tls_result['score'] / TLS_MAX, 1.0)
    net_norm = min(net_result['score'] / NET_MAX, 1.0)
    url_norm = min(url_result['score'] / URL_MAX, 1.0)

    total = (dns_norm * W_DNS +
             tls_norm * W_TLS +
             net_norm * W_NETWORK +
             url_norm * W_URL)

    if total >= 0.25:
        verdict = 'HIGH RISK — MALICIOUS'
        color   = 'red'
    elif total >= 0.15:
        verdict = 'MEDIUM RISK — SUSPICIOUS'
        color   = 'orange'
    else:
        verdict = 'LOW RISK — LIKELY BENIGN'
        color   = 'green'

    return {
        'total':        round(total, 4),
        'percentage':   round(total * 100, 1),
        'verdict':      verdict,
        'color':        color,
        'dns_norm':     round(dns_norm * 100, 1),
        'tls_norm':     round(tls_norm * 100, 1),
        'network_norm': round(net_norm * 100, 1),
        'url_norm':     round(url_norm * 100, 1),
    }

# ============================================================
# HELPER FUNCTIONS
# ============================================================
def calculate_entropy(s):
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def calculate_continuation(url):
    if len(url) < 2:
        return 1.0
    cont = sum(1 for i in range(1, len(url))
               if url[i].isalpha() == url[i-1].isalpha())
    return round(cont / (len(url) - 1), 4)