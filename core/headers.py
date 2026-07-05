import urllib.request
import urllib.error
import ssl
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


# Each header: (header_name, description, severity, what_to_check)
SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "description": "Enforces HTTPS — prevents SSL stripping attacks",
        "severity": "High",
        "check": lambda v: "max-age" in v.lower(),
        "bad_values": [],
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "name": "Content-Security-Policy",
        "description": "Controls which resources can load — prevents XSS",
        "severity": "High",
        "check": lambda v: len(v) > 0,
        "bad_values": ["unsafe-inline", "unsafe-eval", "*"],
        "recommendation": "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    {
        "name": "X-Frame-Options",
        "description": "Prevents clickjacking via iframe embedding",
        "severity": "Medium",
        "check": lambda v: v.upper() in ["DENY", "SAMEORIGIN"],
        "bad_values": ["ALLOW-FROM *"],
        "recommendation": "X-Frame-Options: DENY",
    },
    {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME sniffing — stops browser from guessing content type",
        "severity": "Medium",
        "check": lambda v: v.lower() == "nosniff",
        "bad_values": [],
        "recommendation": "X-Content-Type-Options: nosniff",
    },
    {
        "name": "Referrer-Policy",
        "description": "Controls how much referrer info is sent to other sites",
        "severity": "Low",
        "check": lambda v: v.lower() in [
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "origin", "no-referrer-when-downgrade"
        ],
        "bad_values": ["unsafe-url"],
        "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "name": "Permissions-Policy",
        "description": "Controls browser feature access (camera, microphone, geolocation)",
        "severity": "Low",
        "check": lambda v: len(v) > 0,
        "bad_values": [],
        "recommendation": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    {
        "name": "X-XSS-Protection",
        "description": "Legacy XSS filter for older browsers",
        "severity": "Info",
        "check": lambda v: v.startswith("1"),
        "bad_values": ["0"],
        "recommendation": "X-XSS-Protection: 1; mode=block",
    },
]

# Headers that reveal tech stack (fingerprinting)
LEAKY_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Wordpress-Cache",
    "X-Runtime",
]

# Dangerous cookie flag combinations
COOKIE_FLAGS = ["HttpOnly", "Secure", "SameSite"]


class HeaderAuditor:
    """
    Audits HTTP response headers for security misconfigurations.
    Checks for missing security headers, leaky tech headers, and cookie flags.
    """

    def __init__(self, hosts, out_dir, threads, timeout, log):
        self.hosts   = hosts
        self.out_dir = out_dir
        self.threads = threads
        self.timeout = timeout
        self.log     = log
        self.ctx     = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode    = ssl.CERT_NONE

    def run(self):
        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._audit_host, h): h for h in self.hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    self._log_result(result)

        # Save JSON
        out_path = os.path.join(self.out_dir, "header_audit.json")
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)

        self.log.info(f"Header audit saved to {out_path}")
        return results

    def _audit_host(self, host):
        try:
            req = urllib.request.Request(
                host,
                headers={"User-Agent": "Mozilla/5.0 ReconBot/1.0"}
            )
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)
            headers = dict(resp.headers)
            status  = resp.getcode()
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
            status  = e.code
        except Exception:
            return None

        headers_lower = {k.lower(): v for k, v in headers.items()}

        missing_headers  = []
        present_headers  = []
        leaky_headers    = []
        weak_headers     = []
        cookie_issues    = []

        # Check security headers
        for h in SECURITY_HEADERS:
            hname = h["name"].lower()
            if hname not in headers_lower:
                missing_headers.append({
                    "header": h["name"],
                    "description": h["description"],
                    "severity": h["severity"],
                    "recommendation": h["recommendation"],
                })
            else:
                val = headers_lower[hname]
                present_headers.append({"header": h["name"], "value": val})
                # Check for bad values
                for bad in h.get("bad_values", []):
                    if bad.lower() in val.lower():
                        weak_headers.append({
                            "header": h["name"],
                            "value": val,
                            "issue": f"Contains dangerous value: '{bad}'",
                            "severity": h["severity"],
                        })

        # Check leaky headers
        for lh in LEAKY_HEADERS:
            if lh.lower() in headers_lower:
                leaky_headers.append({
                    "header": lh,
                    "value": headers_lower[lh.lower()],
                    "issue": "Reveals technology stack — aids attacker fingerprinting",
                })

        # Check cookie flags
        set_cookie = headers_lower.get("set-cookie", "")
        if set_cookie:
            for flag in COOKIE_FLAGS:
                if flag.lower() not in set_cookie.lower():
                    cookie_issues.append(f"Missing '{flag}' flag on Set-Cookie")

        # Score calculation (0–100)
        total   = len(SECURITY_HEADERS)
        present = total - len(missing_headers)
        score   = round((present / total) * 100)
        grade   = self._grade(score)

        return {
            "url":             host,
            "status":          status,
            "score":           score,
            "grade":           grade,
            "missing_headers": missing_headers,
            "present_headers": present_headers,
            "weak_headers":    weak_headers,
            "leaky_headers":   leaky_headers,
            "cookie_issues":   cookie_issues,
            "raw_headers":     dict(headers),
        }

    def _grade(self, score):
        if score >= 90: return "A"
        if score >= 75: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"

    def _log_result(self, result):
        grade = result["grade"]
        color_map = {"A": "\033[92m", "B": "\033[92m", "C": "\033[93m", "D": "\033[91m", "F": "\033[91m"}
        c = color_map.get(grade, "")
        reset = "\033[0m"
        self.log.item(
            f"{result['url']} — Grade: {c}{grade}{reset} ({result['score']}/100) "
            f"— Missing: {len(result['missing_headers'])} headers"
        )
        if result["leaky_headers"]:
            for lh in result["leaky_headers"]:
                self.log.warning(f"  Leaky: {lh['header']}: {lh['value']}")
