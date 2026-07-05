import subprocess
import shutil
import os


class Screenshotter:
    """
    Takes screenshots of live hosts using gowitness.
    Falls back to a notice if gowitness is not installed.
    """

    def __init__(self, hosts, out_dir, log):
        self.hosts      = hosts
        self.out_dir    = out_dir
        self.log        = log
        self.shots_dir  = os.path.join(out_dir, "screenshots")
        os.makedirs(self.shots_dir, exist_ok=True)

    def run(self):
        if not shutil.which("gowitness"):
            self.log.warning("gowitness not found — skipping screenshots")
            self.log.warning("Install: go install github.com/sensepost/gowitness@latest")
            return []

        live_file = os.path.join(self.out_dir, "live_hosts.txt")
        if not os.path.exists(live_file):
            self.log.warning("live_hosts.txt not found — skipping screenshots")
            return []

        self.log.info(f"Taking screenshots of {len(self.hosts)} hosts...")

        try:
            subprocess.run(
                [
                    "gowitness", "file",
                    "-f", live_file,
                    "--screenshot-path", self.shots_dir,
                    "--no-http",
                ],
                capture_output=True, text=True, timeout=600
            )
        except subprocess.TimeoutExpired:
            self.log.warning("gowitness timed out")
        except Exception as e:
            self.log.error(f"gowitness error: {e}")

        # Collect captured screenshots
        screenshots = []
        for fname in os.listdir(self.shots_dir):
            if fname.endswith(".png"):
                screenshots.append(os.path.join(self.shots_dir, fname))

        self.log.info(f"Screenshots saved to {self.shots_dir}")
        return screenshots
