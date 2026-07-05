import subprocess
import os
import shutil
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error
import ssl


class HostProber:
    """
    Probes subdomains on ports 80/443 to find live HTTP/HTTPS hosts.
    Uses httpx if installed, otherwise falls back to pure Python requests.
    """

    def __init__(self, subdomains, out_dir, threads, timeout, log):
        self.subdomains = subdomains
        self.out_dir    = out_dir
        self.threads    = threads
        self.timeout    = timeout
        self.log        = log
        self.live_file  = os.path.join(out_dir, "live_hosts.txt")

    def run(self):
        if shutil.which("httpx"):
            self.log.info("Using httpx for probing...")
            live = self._run_httpx()
        else:
            self.log.warning("httpx not found — using built-in prober")
            self.log.warning("Install httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            live = self._builtin_probe()

        with open(self.live_file, "w") as f:
            f.write("\n".join(live))

        self.log.info(f"Live hosts saved to {self.live_file}")
        return live

    def _run_httpx(self):
        subs_file = os.path.join(self.out_dir, "subdomains.txt")
        try:
            result = subprocess.run(
                [
                    "httpx", "-l", subs_file,
                    "-silent",
                    "-threads", str(self.threads),
                    "-timeout", str(self.timeout),
                    "-follow-redirects",
                    "-status-code",
                    "-title",
                    "-web-server",
                    "-tech-detect",
                    "-o", os.path.join(self.out_dir, "httpx_full.txt"),
                ],
                capture_output=True, text=True, timeout=300
            )
            hosts = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    # httpx outputs URL as first token
                    url = line.split()[0]
                    hosts.append(url)
                    self.log.item(line)
            return hosts
        except subprocess.TimeoutExpired:
            self.log.warning("httpx timed out")
            return []
        except Exception as e:
            self.log.error(f"httpx error: {e}")
            return []

    def _builtin_probe(self):
        """Pure Python fallback — probes http:// and https:// on port 80/443."""
        live = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        def probe(subdomain):
            results = []
            for scheme in ["https", "http"]:
                url = f"{scheme}://{subdomain}"
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "ReconBot/1.0"})
                    resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx if scheme == "https" else None)
                    status = resp.getcode()
                    server = resp.headers.get("Server", "Unknown")
                    title  = self._extract_title(resp.read(4096).decode("utf-8", errors="ignore"))
                    info = f"{url} [{status}] [{server}] [{title}]"
                    self.log.item(info)
                    results.append(url)
                    break  # If https works, skip http
                except Exception:
                    continue
            return results

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe, s): s for s in self.subdomains}
            for future in as_completed(futures):
                live.extend(future.result())

        return live

    def _extract_title(self, html):
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:60]
        return "No title"
