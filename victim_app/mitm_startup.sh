#!/bin/bash

# Navigate to the project directory
cd ~/WebCeptor-Project

# Activate the virtual environment (if exists)
source venv/bin/activate

# Run mitmdump silently with necessary flags
nohup mitmdump --mode regular@8080 \
    --listen-host 127.0.0.1 \
    --ssl-insecure \
    -s ~/WebCeptor-Project/victim_app/mitm_interceptor.py > /dev/null 2>&1 &

# Store process ID for later stopping
echo $! > ~/.mitmproxy_pid
