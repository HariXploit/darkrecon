# DarkRecon 🔍
> Personal Bug Bounty Recon Automation Tool

A Python/Bash pipeline that automates end-to-end recon for bug bounty hunting.  
Takes a target domain and runs the full recon lifecycle automatically — subdomains → live hosts → security headers → screenshots → HTML report.
---

## Features

| Phase | What it does | Tools used |
|---|---|---|
| Subdomain Enumeration | Finds all subdomains via passive + brute-force | subfinder, amass, built-in DNS |
| Host Probing | Checks which subdomains are live on HTTP/HTTPS | httpx, built-in fallback |
| Header Audit | Checks 7 security headers + cookie flags + tech leakage | Pure Python |
| Screenshots | Visual snapshots of every live host | gowitness |
| Report | Clean HTML + JSON report with grades and findings | Built-in |

---

## Installation

```bash
git clone https://github.com/HariXploit/darkrecon
cd darkrecon
chmod +x install.sh && ./install.sh
```

Or manually:
```bash
pip3 install -r requirements.txt --break-system-packages

# Install Go tools (optional but recommended)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/sensepost/gowitness@latest
go install -v github.com/owasp-amass/amass/v4/...@master
```

> **Note:** DarkRecon works without Go tools — it falls back to built-in Python DNS enumeration and HTTP probing. Go tools make it faster and find more.

---

## Usage

```bash
# Basic run
python3 recon.py -d example.com

# Skip screenshots (faster)
python3 recon.py -d example.com --skip-screenshots

# Custom output dir and threads
python3 recon.py -d example.com --output /tmp/recon --threads 20

# Skip amass (much faster, uses subfinder + built-in only)
python3 recon.py -d example.com --skip-amass

# Run only a specific phase
python3 recon.py -d example.com --only subdomains
python3 recon.py -d example.com --only headers

# Silent mode (no banner/progress)
python3 recon.py -d example.com --silent
```

---

## Output Structure
output/
└── example.com_20240101_120000/
├── report.html          ← Main HTML report (open in browser)
├── recon_results.json   ← Full JSON data
├── subdomains.txt       ← All discovered subdomains
├── live_hosts.txt       ← Live HTTP/HTTPS hosts
├── header_audit.json    ← Detailed header findings
├── httpx_full.txt       ← Full httpx output
└── screenshots/         ← gowitness PNG screenshots
---

## Security Headers Checked

| Header | Severity | What it protects against |
|---|---|---|
| Strict-Transport-Security | High | SSL stripping, MITM |
| Content-Security-Policy | High | XSS, data injection |
| X-Frame-Options | Medium | Clickjacking |
| X-Content-Type-Options | Medium | MIME sniffing XSS |
| Referrer-Policy | Low | Info leakage |
| Permissions-Policy | Low | Feature abuse |
| X-XSS-Protection | Info | Legacy XSS filter |

Also checks for:
- **Tech stack leakage** via `Server`, `X-Powered-By`, `X-AspNet-Version` etc.
- **Cookie flag issues** — missing `HttpOnly`, `Secure`, `SameSite`
- **Weak header values** — `unsafe-inline` in CSP, `ALLOW-FROM *` in X-Frame-Options

---

## Legal Notice

This tool is for **authorized security testing only**.  
Only use against targets you have explicit permission to test.  
Bug bounty programs: always read the program scope before running recon.

---

## Contributing

PRs welcome. Ideas for next features:
- [ ] Wayback Machine URL mining
- [ ] JS file secret scanning
- [ ] Open redirect detection
- [ ] CORS misconfiguration check
- [ ] Nuclei integration

---

## Author

Built by [HariXploit](https://github.com/HariXploit) for bug bounty recon automation.
