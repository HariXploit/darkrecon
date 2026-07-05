#!/usr/bin/env python3
"""
DarkRecon - Personal Bug Bounty Recon Automation Tool
Author: HariXploit
GitHub: github.com/HariXploit/darkrecon
"""

import argparse
import os
import sys
import time
from datetime import datetime
from core.subdomain import SubdomainEnumerator
from core.probing import HostProber
from core.headers import HeaderAuditor
from core.screenshot import Screenshotter
from core.reporter import ReportGenerator
from utils.logger import Logger
from utils.config import Config

BANNER = """
██████╗  █████╗ ██████╗ ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗
██║  ██║███████║██████╔╝█████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗
██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║
  Bug Bounty Recon Automation Tool v1.0
  github.com/HariXploit/darkrecon
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="DarkRecon — automated bug bounty recon pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py -d example.com
  python3 recon.py -d example.com --skip-screenshots
  python3 recon.py -d example.com --output /tmp/recon --threads 20
  python3 recon.py -d example.com --only subdomains
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: ./output)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--skip-screenshots", action="store_true", help="Skip gowitness screenshots")
    parser.add_argument("--skip-amass", action="store_true", help="Skip amass (faster, uses subfinder only)")
    parser.add_argument("--only", choices=["subdomains", "probe", "headers", "report"],
                        help="Run only a specific phase")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument("--silent", action="store_true", help="Suppress banner and progress output")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.silent:
        print(BANNER)

    config = Config(args)
    log = Logger(silent=args.silent)
    target = args.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(args.output, f"{target}_{timestamp}")
    os.makedirs(out_dir, exist_ok=True)

    log.info(f"Target     : {target}")
    log.info(f"Output dir : {out_dir}")
    log.info(f"Threads    : {args.threads}")
    log.info(f"Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.banner("Starting DarkRecon Pipeline")

    results = {
        "target": target,
        "timestamp": timestamp,
        "out_dir": out_dir,
        "subdomains": [],
        "live_hosts": [],
        "header_results": [],
        "screenshots": [],
    }

    start_time = time.time()

    if args.only in (None, "subdomains"):
        log.phase("Phase 1: Subdomain Enumeration")
        enumerator = SubdomainEnumerator(
            target=target,
            out_dir=out_dir,
            skip_amass=args.skip_amass,
            threads=args.threads,
            log=log,
        )
        results["subdomains"] = enumerator.run()
        log.success(f"Found {len(results['subdomains'])} unique subdomains")

    if args.only in (None, "probe"):
        log.phase("Phase 2: Probing Live Hosts (httpx)")
        prober = HostProber(
            subdomains=results["subdomains"],
            out_dir=out_dir,
            threads=args.threads,
            timeout=args.timeout,
            log=log,
        )
        results["live_hosts"] = prober.run()
        log.success(f"Found {len(results['live_hosts'])} live hosts")

    if args.only in (None, "headers"):
        log.phase("Phase 3: Security Header Audit")
        auditor = HeaderAuditor(
            hosts=results["live_hosts"],
            out_dir=out_dir,
            threads=args.threads,
            timeout=args.timeout,
            log=log,
        )
        results["header_results"] = auditor.run()
        missing_count = sum(1 for h in results["header_results"] if h["missing_headers"])
        log.success(f"Audited {len(results['header_results'])} hosts — {missing_count} have missing security headers")

    if not args.skip_screenshots and args.only in (None, "report"):
        log.phase("Phase 4: Screenshots (gowitness)")
        screenshotter = Screenshotter(
            hosts=results["live_hosts"],
            out_dir=out_dir,
            log=log,
        )
        results["screenshots"] = screenshotter.run()
        log.success(f"Captured {len(results['screenshots'])} screenshots")

    log.phase("Phase 5: Generating Report")
    elapsed = round(time.time() - start_time, 2)
    results["elapsed"] = elapsed
    reporter = ReportGenerator(results=results, out_dir=out_dir, log=log)
    report_path = reporter.run()

    log.banner("DarkRecon Complete")
    log.success(f"Time elapsed  : {elapsed}s")
    log.success(f"Subdomains    : {len(results['subdomains'])}")
    log.success(f"Live hosts    : {len(results['live_hosts'])}")
    log.success(f"Header issues : {sum(1 for h in results['header_results'] if h.get('missing_headers'))}")
    log.success(f"Report        : {report_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(0)
