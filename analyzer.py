import re
from urllib.parse import urlparse
import tldextract

# Known suspicious TLDs
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.pw', '.info', '.click'}

# Known URL shorteners
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'short.link', 'goo.gl',
    'lnk.co', 'buff.ly', 'adf.ly', 'is.gd'
}

# Known brand names (for impersonation detection)
BRANDS = {'google', 'gmail', 'paypal', 'amazon', 'microsoft', 'apple', 'facebook', 'bank', 'twitter', 'linkedin'}

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = {'login', 'verify', 'account', 'secure', 'update', 'confirm', 'signin', 'auth', 'password', 'payment'}


def analyze_url(url):
    """
    Analyze a URL and return a risk score with detailed checks.
    Returns: {
        'score': 0-100,
        'level': 'safe' | 'suspicious' | 'dangerous',
        'checks': [{'name': str, 'score': int, 'triggered': bool, 'description': str}],
        'domain': str,
        'whois': dict or None
    }
    """
    checks = []
    total_score = 0

    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        scheme = parsed.scheme
    except:
        return {
            'score': 0,
            'level': 'error',
            'checks': [],
            'domain': url,
            'whois': None,
            'message': 'Invalid URL format'
        }

    # Check 1: IP address in URL
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ip_check = bool(re.search(ip_pattern, domain))
    if ip_check:
        total_score += 20
    checks.append({
        'name': 'IP Address',
        'score': 20,
        'triggered': ip_check,
        'description': 'URL contains IP address instead of domain name'
    })

    # Check 2: @ symbol in URL
    at_check = '@' in url
    if at_check:
        total_score += 10
    checks.append({
        'name': '@ Symbol',
        'score': 10,
        'triggered': at_check,
        'description': 'URL contains @ symbol (browser ignores text before it)'
    })

    # Check 3: Suspicious keywords in URL
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    keywords_check = len(keywords_found) > 0
    if keywords_check:
        total_score += 20
    checks.append({
        'name': 'Suspicious Keywords',
        'score': 20,
        'triggered': keywords_check,
        'description': f'Found suspicious keywords: {", ".join(keywords_found[:3])}' if keywords_found else ''
    })

    # Check 4: URL length
    length_check = len(url) > 75
    if length_check:
        total_score += 10
    checks.append({
        'name': 'Excessive URL Length',
        'score': 10,
        'triggered': length_check,
        'description': 'URL is longer than 75 characters (may hide destination)'
    })

    # Check 5: Excessive subdomains
    subdomain_count = domain.count('.')
    subdomains_check = subdomain_count > 3
    if subdomains_check:
        total_score += 10
    checks.append({
        'name': 'Excessive Subdomains',
        'score': 10,
        'triggered': subdomains_check,
        'description': f'Domain has {subdomain_count} dots (suspicious pattern)'
    })

    # Check 6: Suspicious TLD
    extracted = tldextract.extract(url)
    tld = f'.{extracted.suffix}' if extracted.suffix else ''
    tld_check = tld.lower() in SUSPICIOUS_TLDS
    if tld_check:
        total_score += 25
    checks.append({
        'name': 'Suspicious TLD',
        'score': 25,
        'triggered': tld_check,
        'description': f'Domain uses suspicious TLD: {tld}'
    })

    # Check 7: HTTP instead of HTTPS
    http_check = scheme == 'http'
    if http_check:
        total_score += 25
    checks.append({
        'name': 'Insecure Protocol',
        'score': 25,
        'triggered': http_check,
        'description': 'Uses HTTP instead of HTTPS (not encrypted)'
    })

    # Check 8: Hyphens in domain
    hyphens_count = domain.count('-')
    hyphens_check = hyphens_count > 2
    if hyphens_check:
        total_score += 5
    checks.append({
        'name': 'Excessive Hyphens',
        'score': 5,
        'triggered': hyphens_check,
        'description': f'Domain contains {hyphens_count} hyphens (may indicate typosquatting)'
    })

    # Check 9: URL shortener
    shortener_check = any(short in domain for short in SHORTENERS)
    if shortener_check:
        total_score += 51
    checks.append({
        'name': 'URL Shortener',
        'score': 51,
        'triggered': shortener_check,
        'description': 'URL is shortened (destination hidden)'
    })

    # Check 10: Brand impersonation
    domain_base = extracted.domain.lower() if extracted.domain else ''
    brand_check = any(brand in domain_base for brand in BRANDS) and domain_base not in ['google', 'paypal', 'amazon', 'microsoft', 'apple', 'facebook', 'twitter', 'linkedin']
    if brand_check:
        total_score += 5
    checks.append({
        'name': 'Brand Impersonation',
        'score': 5,
        'triggered': brand_check,
        'description': 'Domain may be impersonating a known brand'
    })

    # Cap score at 100
    total_score = min(total_score, 100)

    # Determine risk level (more aggressive thresholds)
    if total_score < 20:
        level = 'safe'
    elif total_score < 50:
        level = 'suspicious'
    else:
        level = 'dangerous'

    return {
        'score': total_score,
        'level': level,
        'checks': checks,
        'domain': domain,
        'tld': tld,
        'whois': None  # Could add WHOIS lookup here in the future
    }
