import sys
from datetime import datetime


class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


class Logger:
    def __init__(self, silent=False):
        self.silent = silent

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S")

    def _print(self, msg):
        if not self.silent:
            print(msg)

    def info(self, msg):
        self._print(f"{Colors.CYAN}[{self._ts()}] [INFO]{Colors.RESET} {msg}")

    def success(self, msg):
        self._print(f"{Colors.GREEN}[{self._ts()}] [+]{Colors.RESET} {msg}")

    def warning(self, msg):
        self._print(f"{Colors.YELLOW}[{self._ts()}] [!]{Colors.RESET} {msg}")

    def error(self, msg):
        self._print(f"{Colors.RED}[{self._ts()}] [ERROR]{Colors.RESET} {msg}")

    def phase(self, msg):
        self._print(f"\n{Colors.BOLD}{Colors.MAGENTA}[{self._ts()}] >>> {msg}{Colors.RESET}")

    def banner(self, msg):
        line = "─" * 50
        self._print(f"\n{Colors.BOLD}{Colors.BLUE}{line}")
        self._print(f"  {msg}")
        self._print(f"{line}{Colors.RESET}\n")

    def item(self, msg):
        self._print(f"  {Colors.WHITE}→{Colors.RESET} {msg}")

    def write_log(self, path, lines):
        with open(path, "w") as f:
            f.write("\n".join(lines))
