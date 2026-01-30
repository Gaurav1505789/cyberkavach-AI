import re
import ipaddress
import unicodedata
from collections import Counter

SUSPICIOUS_KEYWORDS = ['free', 'click', 'verify', 'confirm', 'urgent', 'update', 'login', 'secure', 'bank', 'account', 'claim', 'prize', 'win']
DOWNLOAD_EXTS = ['.exe', '.msi', '.zip', '.rar', '.jar', '.apk', '.dmg', '.pkg', '.bat', '.scr', '.js', '.ps1', '.tar', '.7z', '.iso']
DOWNLOAD_KEYWORDS = ['download', 'dl', 'attachment', 'installer', 'setup']

ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff'}

# Reserved special-use top-level labels per RFC 2606 and related guidance
RESERVED_TLDS = {'test', 'example', 'invalid', 'localhost'}


def _is_valid_hostname(hostname: str) -> tuple:
    """Basic syntactic hostname validation. Returns (bool, reason_if_any)."""
    if not hostname:
        return False, 'Empty host'

    # Disallow localhost explicitly
    if hostname.lower() in ('localhost', '127.0.0.1', '::1'):
        return False, 'Host is localhost or loopback'

    # If it looks like an IP, validate with ipaddress
    try:
        ip = ipaddress.ip_address(hostname)
        # Disallow private, loopback, link-local, multicast, or reserved addresses as invalid for domain validation
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False, 'IP host is private, loopback, link-local, multicast, or reserved'
        # Public IPs are considered valid for syntactic purposes
        return True, ''
    except Exception:
        pass

    # Hostname rules per RFC-like constraints
    if len(hostname) > 253:
        return False, 'Hostname too long'

    labels = hostname.split('.')
    # Require at least one dot (e.g., 'example' alone is not a valid public hostname here)
    if len(labels) < 2:
        return False, 'Hostname missing dot/TLD'

    for label in labels:
        if not label:
            return False, 'Empty label in hostname'
        if len(label) > 63:
            return False, 'Hostname label too long'
        if not re.match(r'^[A-Za-z0-9-]+$', label):
            return False, f'Invalid characters in label `{label}`'
        if label.startswith('-') or label.endswith('-'):
            return False, f'Label `{label}` starts/ends with hyphen'

    # Basic TLD check: last label length >=2
    if len(labels[-1]) < 2:
        return False, 'Top-level domain too short'

    # Check for reserved special-use top-level labels (e.g., .test, .example)
    if labels[-1].lower() in RESERVED_TLDS:
        return False, f'Top-level domain "{labels[-1]}" is reserved/special-use'

    return True, ''


def _tokenize(text: str):
    """Split text into alphanumeric tokens (words)."""
    if not text:
        return []
    tokens = re.split(r'[^A-Za-z0-9]+', text)
    return [t for t in tokens if t]


def _detect_unusual_chars(text: str):
    """Return list of findings about unusual unicode characters or symbols."""
    findings = []
    if not text:
        return findings

    # Non-ASCII characters
    non_ascii = [c for c in text if ord(c) > 127]
    if non_ascii:
        # show unique categories/counts
        ctr = Counter(non_ascii)
        sample = ''.join(list(ctr.keys())[:6])
        findings.append(f'Non-ASCII characters present (sample: {sample})')

    # Zero-width characters
    zw = [c for c in text if c in ZERO_WIDTH_CHARS]
    if zw:
        findings.append('Zero-width or invisible characters present')

    # Combining marks
    combining = [c for c in text if unicodedata.category(c).startswith('M')]
    if combining:
        findings.append('Combining Unicode marks present')

    # Mixed script detection (very heuristic): check if more than one script in letters
    letters = [c for c in text if c.isalpha()]
    scripts = set()
    for c in letters:
        try:
            name = unicodedata.name(c)
            scripts.add(name.split(' ')[0])
        except Exception:
            scripts.add('UNKNOWN')
    if len(scripts) > 1:
        findings.append('Mixed Unicode scripts detected (e.g., Latin+Cyrillic)')

    # Unusual punctuation outside common URL chars
    unusual_punct = [c for c in text if c in "<>#{}|\\^~[]`"]
    if unusual_punct:
        findings.append(f'Unusual punctuation present: {set(unusual_punct)}')

    return findings


def rule_check(normalized_info: dict) -> tuple:
    """Apply deterministic rules to determine if URL is suspicious.

    Returns (is_suspicious: bool, reasons: list[str], domain_valid: bool, unusual_findings: list[str])
    """
    reasons = []
    unusual_findings = []
    # initialize hard and soft reason lists early so all rules can append safely
    hard_reasons = []
    soft_reasons = []

    url = normalized_info.get('normalized_url') or ''
    netloc = normalized_info.get('netloc') or ''
    path = normalized_info.get('path') or ''
    query = normalized_info.get('query') or ''
    scheme = normalized_info.get('scheme') or ''
    is_ip = normalized_info.get('is_ip', False)
    is_punycode = normalized_info.get('is_punycode', False)

    # Rule: contains '@'
    if '@' in url:
        hard_reasons.append("Contains '@' symbol (likely credential-stealing redirect or obfuscation)")

    # Rule: IP address in host
    if is_ip:
        hard_reasons.append('Host is an IP address instead of a domain')
        # Check for private or loopback
        try:
            host = netloc.split(':')[0]
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback:
                hard_reasons.append('IP host is private or loopback')
        except Exception:
            pass

    # Rule: punycode (IDN) used
    if is_punycode:
        hard_reasons.append('Uses punycode (IDN) which can be used to spoof domain')

    # Rule: suspicious keywords in netloc or path
    lower = (netloc + ' ' + path + ' ' + query).lower()
    found_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in lower]
    if found_keywords:
        hard_reasons.append('Suspicious keywords found: ' + ', '.join(found_keywords))

    # Rule: missing HTTPS -> treat as soft warning (not decisive by itself)
    if scheme != 'https':
        soft_reasons.append('Not HTTPS (no TLS)')

    # Rule: url too long
    if len(url) > 100:
        hard_reasons.append('Excessive length')

    # Rule: too many subdomains
    subdomains = netloc.split('.')
    if len(subdomains) - 1 > 3:
        hard_reasons.append('Unusually deep subdomain nesting')

    # Rule: suspicious characters or ports
    if re.search(r'[^a-zA-Z0-9\-._:/?=&%]', url):
        hard_reasons.append('Unusual characters in URL')

    # Rule: suspicious download links (file extensions or keywords)
    p = path.lower()
    q = query.lower()
    file_suspicious = False
    for ext in DOWNLOAD_EXTS:
        if p.endswith(ext) or ext in q:
            file_suspicious = True
            hard_reasons.append(f'Suspicious download extension found: {ext}')
            break
    if not file_suspicious:
        if any(k in p or k in q for k in DOWNLOAD_KEYWORDS):
            hard_reasons.append('Download-related keywords found in path or query')
            file_suspicious = True

    # Token-level checks
    tokens = _tokenize(netloc + ' ' + path)
    token_issues = []
    for t in tokens:
        # Very long token
        if len(t) > 30:
            token_issues.append(f'Long token `{t[:30]}...`')
        # High digit ratio
        digits = sum(c.isdigit() for c in t)
        if digits > 0 and digits / len(t) > 0.6:
            token_issues.append(f'Token with many digits: `{t}`')
        # Repeated characters
        if any(ch * 5 in t for ch in set(t)):
            token_issues.append(f'Excessive repeated character in token: `{t}`')
        # Mixed letter/digit gibberish heuristic
        letters = sum(c.isalpha() for c in t)
        if letters > 0 and (letters / len(t) < 0.3):
            token_issues.append(f'Gibberish token: `{t}`')

    if token_issues:
        hard_reasons.append('Token-level anomalies: ' + '; '.join(token_issues[:5]))

    # Unusual unicode/symbol checks
    unusual_findings = _detect_unusual_chars(netloc + path + query)
    for u in unusual_findings:
        hard_reasons.append(u)

    # Domain syntactic validity check
    host = netloc.split(':')[0]
    domain_valid, domain_reason = _is_valid_hostname(host)
    if not domain_valid:
        hard_reasons.append('Domain validation failed: ' + domain_reason)

    # Rule: suspicious download links (file extensions or keywords)
    # (previously appended to reasons already)

    # Consolidate reasons: hard reasons first, then soft reasons
    reasons = hard_reasons + soft_reasons

    is_suspicious = len(hard_reasons) > 0
    return is_suspicious, reasons, domain_valid, unusual_findings
