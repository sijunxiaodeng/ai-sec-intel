"""Exercise a fresh offline demo over real localhost HTTP, then stop our process."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="offline-demo-check-") as directory:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        base = "http://127.0.0.1:%d" % port
        with (Path(directory) / "server.log").open("w+") as log:
            child = subprocess.Popen([sys.executable, "scripts/offline_demo.py", "--data-directory",
                                      str(Path(directory) / "data"), "--port", str(port)],
                                     cwd=ROOT, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if child.poll() is not None:
                        log.seek(0)
                        raise RuntimeError("Offline startup failed: " + log.read()[-3000:])
                    try:
                        with urllib.request.urlopen(base + "/api/overview", timeout=2) as response:
                            overview = json.load(response)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Offline demo readiness deadline exceeded") from None
                        time.sleep(.2)
                assert overview["offline_demo"] is True and overview["llm_ready"] is False
                subprocess.run([sys.executable, "scripts/check_container_integration.py", "--base-url", base,
                                "--preloaded"],
                               cwd=ROOT, check=True, timeout=40)
                print(json.dumps({"offline_http_demo": "passed", "synthetic": True}))
            finally:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)


if __name__ == "__main__":
    main()
