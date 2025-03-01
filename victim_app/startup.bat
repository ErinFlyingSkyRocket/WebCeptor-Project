@echo off
cd /d "%~dp0"

:: Start mitmdump in a new command window (visible)
:: - Runs in regular proxy mode on port 8080
:: - Listens only on localhost (127.0.0.1)
:: - Bypasses SSL/TLS certificate verification
:: - Uses the script "mitm_interceptor.py" for processing traffic
start cmd /k mitmdump --mode regular@8080 --listen-host 127.0.0.1 --ssl-insecure -s mitm_interceptor.py

:: Alternative: Start mitmdump as a background process (hidden window)
:: Run mitmdump in the background with no visible window using WScript
:: wscript.exe hidden_startup.vbs

exit
