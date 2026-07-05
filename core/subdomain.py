import subprocess
import os
import shutil


class SubdomainEnumerator:
    """
    Runs subdomain enumeration using subfinder and optionally amass.
    Falls back to a pure-Python DNS brute-force if tools are not installed.
    """

    WORDLIST = [
        "www", "mail", "ftp", "api", "dev", "staging", "test", "beta",
        "admin", "portal", "dashboard", "app", "mobile", "cdn", "static",
        "assets", "media", "upload", "download", "blog", "shop", "store",
        "support", "help", "docs", "wiki", "status", "monitor", "vpn",
        "git", "gitlab", "jenkins", "jira", "confluence", "db", "database",
        "mysql", "postgres", "redis", "elasticsearch", "kibana", "grafana",
        "s3", "storage", "backup", "auth", "login", "sso", "oauth",
        "internal", "intranet", "corp", "old", "legacy", "v2", "v1",
        "sandbox", "preview", "preprod", "prod", "uat", "qa",
        "webmail", "smtp", "imap", "pop", "mx", "ns1", "ns2",
        "remote", "vpn", "proxy", "gateway", "api2", "rest", "graphql",
    ]

    def __init__(self, target, out_dir, skip_amass, threads, log):
        self.target     = target
        self.out_dir    = out_dir
        self.skip_amass = skip_amass
        self.threads    = threads
        self.log        = log
        self.subs_file  = os.path.join(out_dir, "subdomains.txt")

    def run(self):
        subdomains = set()

        # Try subfinder
        if shutil.which("subfinder"):
            self.log.info("Running subfinder...")
            subs = self._run_subfinder()
            self.log.success(f"subfinder found {len(subs)} subdomains")
            subdomains.update(subs)
        else:
            self.log.warning("subfinder not found — install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

        # Try amass
        if not self.skip_amass and shutil.which("amass"):
            self.log.info("Running amass (passive)...")
            subs = self._run_amass()
            self.log.success(f"amass found {len(subs)} subdomains")
            subdomains.update(subs)
        elif not self.skip_amass:
            self.log.warning("amass not found — install: https://github.com/owasp-amass/amass")

        # Always run DNS brute-force as fallback / supplement
        self.log.info("Running DNS brute-force (built-in wordlist)...")
        subs = self._dns_bruteforce()
        self.log.success(f"DNS brute-force found {len(subs)} subdomains")
        subdomains.update(subs)

        # Deduplicate and write
        unique = sorted(subdomains)
        with open(self.subs_file, "w") as f:
            f.write("\n".join(unique))

        self.log.info(f"Saved to {self.subs_file}")
        return unique

    def _run_subfinder(self):
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target, "-silent", "-t", str(self.threads)],
                capture_output=True, text=True, timeout=120
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            self.log.warning("subfinder timed out")
            return []
        except Exception as e:
            self.log.error(f"subfinder error: {e}")
            return []

    def _run_amass(self):
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.target, "-silent"],
                capture_output=True, text=True, timeout=180
            )
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            self.log.warning("amass timed out after 3 minutes")
            return []
        except Exception as e:
            self.log.error(f"amass error: {e}")
            return []

    def _dns_bruteforce(self):
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed

        found = []

        def resolve(sub):
            hostname = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(hostname)
                return hostname
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(resolve, s): s for s in self.WORDLIST}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    self.log.item(f"Resolved: {result}")

        return found
