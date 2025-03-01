#!/bin/bash
cd /home/kali/mitmproxy
source venv/bin/activate  # Activate virtual environment (if used)
nohup mitmdump --mode regular@8080 --listen-host 127.0.0.1 --ssl-insecure -s /home/user/mitmproxy/mitm_interceptor.py > /dev/null 2>&1 &
echo $! > /home/kali/.mitmproxy_pid  # Store the process ID (PID) for stopping later
