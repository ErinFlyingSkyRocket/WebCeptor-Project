#!/bin/bash

# Navigate to the project directory
# cd ~/Downloads/WebCeptor-Project/victim_app

# Choose mode: Transparent (silent) or Non-Transparent (shows logs)

# === NON-TRANSPARENT MODE (SHOWS LOGS IN TERMINAL) ===
# Uncomment this for non-transparent mode:
# mitmdump --mode regular --listen-port 8080 --listen-host 127.0.0.1 --ssl-insecure \
#     -s ~/Downloads/WebCeptor-Project/victim_app/mitm_interceptor.py

# === TRANSPARENT MODE (RUNS IN BACKGROUND, NO OUTPUT) ===
# Uncomment this for transparent mode:
nohup mitmdump --mode regular --listen-port 8080 --listen-host 127.0.0.1 --ssl-insecure \
      -s /home/erin/Downloads/WebCeptor-Project/victim_app/mitm_interceptor.py > /dev/null 2>&1 &


# Store process ID for stopping later
#echo $! > ~/.mitmproxy_pid
