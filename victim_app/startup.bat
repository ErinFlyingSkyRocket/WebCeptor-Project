@echo off
cd /d "%~dp0"

:: Start mitmdump in a new command window (visible)
:: - Runs in regular proxy mode on port 8080
:: - Listens only on localhost (127.0.0.1)
:: - Bypasses SSL/TLS certificate verification
:: - Uses the script "mitm_interceptor.py" for processing traffic
start cmd /k mitmdump --mode regular@8080 --listen-host 127.0.0.1 --ssl-insecure -s mitm_interceptor.py

:: Alternative: Start mitmdump as a background process (hidden window)
:: Uncomment the following line if you want it to run silently in the background
:: powershell -WindowStyle Hidden -Command "Start-Process 'mitmdump' -ArgumentList '--mode regular@8080 --listen-host 127.0.0.1 --ssl-insecure -s mitm_interceptor.py' -NoNewWindow -PassThru"

exit
