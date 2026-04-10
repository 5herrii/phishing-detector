import time
import base64
import requests
import tldextract
from urllib.parse import urlparse
from dotenv import load_dotenv



# =========================
# Configuration
# =========================

load_dotenv(dotenv_path=".env", encoding="utf-8")

API_KEY = os.getenv("VT_API_KEY", "").strip()
print("DEBUG API KEY:", API_KEY)


HIGH_RISK_KEYWORDS = [
    "verify",
    "urgent",
    "suspended",
    "reset-password",
    "confirm",
    "billing",
    "payment",
    "wallet",
    "bank",
    "security-check",
    "limited-access",
    "unlock",
    "recover",
]

LOW_RISK_KEYWORDS = [
    "login",
    "signin",
    "account",
]

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
}

SAFE_BRANDS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "github.com",
    "redshelf.com",
}


# =========================
# Helper Functions
# =========================

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or "unknown"


def extract_hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def contains_ip_in_host(url: str) -> bool:
    try:
        host = urlparse(url).hostname
        if not host:
            return False
        parts = host.split(".")
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    except Exception:
        return False


def is_shortened_url(domain: str) -> bool:
    return domain.lower() in SHORTENERS


def is_safe_brand_domain(domain: str) -> bool:
    return domain.lower() in SAFE_BRANDS


def vt_url_id(url: str) -> str:
    """
    VirusTotal URL identifier:
    base64 of the full URL without '=' padding.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


# =========================
# Local URL Checks
# =========================

def url_checks(url: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    parsed = urlparse(url)
    domain = extract_domain(url)
    hostname = extract_hostname(url)
    full_url_lower = url.lower()

    if parsed.scheme == "http":
        score += 15
        reasons.append("Uses HTTP instead of HTTPS")

    if "@" in url:
        score += 20
        reasons.append("Contains @ symbol, which can hide the real destination")

    if contains_ip_in_host(url):
        score += 25
        reasons.append("Uses an IP address instead of a normal domain")

    if is_shortened_url(domain):
        score += 15
        reasons.append("Uses a known URL shortener")

    if len(full_url_lower) > 120:
        score += 8
        reasons.append("URL is unusually long")

    if full_url_lower.count("-") >= 2:
        score += 10
        reasons.append("Contains multiple hyphens, common in fake domains")

    if hostname.count(".") >= 4:
        score += 8
        reasons.append("Contains many subdomains")

    digit_count = sum(char.isdigit() for char in domain)
    if digit_count >= 4:
        score += 10
        reasons.append("Domain contains many numbers")

    return score, reasons


def keyword_check(url: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    url_lower = url.lower()
    domain = extract_domain(url)

    for word in HIGH_RISK_KEYWORDS:
        if word in url_lower:
            score += 10
            reasons.append(f"High-risk keyword found: {word}")

    for word in LOW_RISK_KEYWORDS:
        if word in url_lower:
            if is_safe_brand_domain(domain):
                score += 1
                reasons.append(f"Common auth keyword found on known domain: {word}")
            else:
                score += 3
                reasons.append(f"Common auth keyword found: {word}")

    return score, reasons


# =========================
# VirusTotal Helpers
# =========================

def score_vt_results(
    malicious: int,
    suspicious: int,
    harmless: int,
    undetected: int,
    label_prefix: str
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if malicious >= 10:
        score += 80
        reasons.append(f"{label_prefix}: {malicious} engines flagged it as malicious (high confidence)")
    elif malicious >= 5:
        score += 60
        reasons.append(f"{label_prefix}: {malicious} engines flagged it as malicious")
    elif malicious >= 1:
        score += 40
        reasons.append(f"{label_prefix}: {malicious} engines flagged it as malicious")

    if suspicious >= 5:
        score += 25
        reasons.append(f"{label_prefix}: {suspicious} engines marked it suspicious")
    elif suspicious >= 1:
        score += 10
        reasons.append(f"{label_prefix}: {suspicious} engines marked it suspicious")

    if malicious == 0 and suspicious == 0:
        reasons.append(
            f"{label_prefix}: no engines flagged it "
            f"(harmless={harmless}, undetected={undetected})"
        )

    return min(score, 100), reasons


def vt_domain_lookup(headers: dict, domain: str) -> tuple[int, list[str], bool]:
    """
    Returns (score, reasons, found_record)
    """
    response = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers=headers,
        timeout=20
    )

    if response.status_code == 401:
        return 0, ["VirusTotal authentication failed: check your API key"], True

    if response.status_code == 429:
        return 0, ["VirusTotal rate limit exceeded: try again later"], True

    if response.status_code == 404:
        return 0, [f"VirusTotal has no domain record for: {domain}"], False

    if response.status_code != 200:
        return 0, [f"VirusTotal domain lookup failed (status {response.status_code})"], True

    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    score, reasons = score_vt_results(
        malicious, suspicious, harmless, undetected, "VirusTotal domain"
    )
    return score, reasons, True


def vt_submit_url(headers: dict, url: str) -> tuple[str | None, list[str]]:
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=20
    )

    if response.status_code == 401:
        return None, ["VirusTotal authentication failed during URL submission"]

    if response.status_code == 429:
        return None, ["VirusTotal rate limit exceeded during URL submission"]

    if response.status_code != 200:
        return None, [f"VirusTotal URL submission failed (status {response.status_code})"]

    submit_json = response.json()
    analysis_id = submit_json.get("data", {}).get("id")
    if not analysis_id:
        return None, ["VirusTotal URL submission succeeded but no analysis ID was returned"]

    return analysis_id, []


def vt_url_analysis_lookup(headers: dict, analysis_id: str) -> tuple[int, list[str]]:
    time.sleep(4)

    response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=20
    )

    if response.status_code == 401:
        return 0, ["VirusTotal authentication failed while fetching URL analysis"]

    if response.status_code == 429:
        return 0, ["VirusTotal rate limit exceeded while fetching URL analysis"]

    if response.status_code != 200:
        return 0, [f"VirusTotal URL analysis fetch failed (status {response.status_code})"]

    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    return score_vt_results(
        malicious, suspicious, harmless, undetected, "VirusTotal URL analysis"
    )


def vt_url_object_lookup(headers: dict, url: str) -> tuple[int, list[str]]:
    """
    Optional second opinion using the exact URL object.
    """
    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{vt_url_id(url)}",
        headers=headers,
        timeout=20
    )

    if response.status_code in (401, 429):
        return 0, []

    if response.status_code != 200:
        return 0, []

    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    return score_vt_results(
        malicious, suspicious, harmless, undetected, "VirusTotal exact URL"
    )


# =========================
# Main VirusTotal Check
# =========================

def check_virustotal(url: str) -> tuple[int, list[str]]:
    """
    Strategy:
    1. Check the root domain reputation.
    2. Check the exact URL object if available.
    3. If exact URL object is missing or weak, submit the URL and fetch analysis.
    """
    if not API_KEY:
        return 0, ["VirusTotal skipped: API key not configured"]

    headers = {"x-apikey": API_KEY}
    domain = extract_domain(url)

    try:
        total_score = 0
        all_reasons: list[str] = []

        # Domain reputation
        domain_score, domain_reasons, domain_found = vt_domain_lookup(headers, domain)
        total_score = max(total_score, domain_score)
        all_reasons.extend(domain_reasons)

        # Exact URL object lookup
        exact_score, exact_reasons = vt_url_object_lookup(headers, url)
        if exact_reasons:
            total_score = max(total_score, exact_score)
            all_reasons.extend(exact_reasons)

        # If domain not found or exact URL had no useful result, submit URL for fresh analysis
        if (not domain_found) or (exact_score == 0 and not exact_reasons):
            analysis_id, submit_reasons = vt_submit_url(headers, url)
            all_reasons.extend(submit_reasons)

            if analysis_id:
                analysis_score, analysis_reasons = vt_url_analysis_lookup(headers, analysis_id)
                total_score = max(total_score, analysis_score)
                all_reasons.extend(analysis_reasons)

        # Remove duplicate reasons while keeping order
        deduped = []
        seen = set()
        for reason in all_reasons:
            if reason not in seen:
                deduped.append(reason)
                seen.add(reason)

        return min(total_score, 100), deduped

    except requests.RequestException as e:
        return 0, [f"VirusTotal request error: {e}"]
    except Exception as e:
        return 0, [f"VirusTotal error: {e}"]


# =========================
# Verdict Logic
# =========================

def get_verdict(score: int) -> str:
    if score >= 70:
        return "HIGH RISK"
    if score >= 40:
        return "SUSPICIOUS"
    return "LIKELY SAFE"


# =========================
# Main Analysis
# =========================

def analyze_url(url: str) -> None:
    url = normalize_url(url)

    total_score = 0
    all_reasons: list[str] = []

    print(f"\nAnalyzing URL: {url}")
    print("-" * 60)

    local_score, local_reasons = url_checks(url)
    total_score += local_score
    all_reasons.extend(local_reasons)

    kw_score, kw_reasons = keyword_check(url)
    total_score += kw_score
    all_reasons.extend(kw_reasons)

    vt_score, vt_reasons = check_virustotal(url)

    # Let VT drive the verdict more strongly than local heuristics
    total_score = max(total_score, vt_score)
    all_reasons.extend(vt_reasons)

    total_score = min(total_score, 100)

    print(f"Domain      : {extract_domain(url)}")
    print(f"Risk Score  : {total_score}/100")
    print(f"Verdict     : {get_verdict(total_score)}")
    print("\nReasons:")

    if all_reasons:
        seen = set()
        for reason in all_reasons:
            if reason not in seen:
                print(f"- {reason}")
                seen.add(reason)
    else:
        print("- No suspicious indicators found")

    print("-" * 60)


# =========================
# Main Program
# =========================

if __name__ == "__main__":
    print("Phishing URL Detector")
    print("Type 'exit' to quit.\n")

    while True:
        user_input = input("Enter a URL to analyze: ").strip()

        if user_input.lower() == "exit":
            print("Goodbye.")
            break

        if not user_input:
            print("Please enter a valid URL.\n")
            continue

        analyze_url(user_input)
        print()
