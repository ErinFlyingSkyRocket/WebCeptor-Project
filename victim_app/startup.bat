@echo off
cd /d "%~dp0"

:: Start mitmdump instance in a visible window
start cmd /k mitmdump --mode regular@8080 --listen-host 127.0.0.1 --ssl-insecure -s mitm_interceptor.py

:: Start mitmdump instance as a background process (no window)
:: powershell -WindowStyle Hidden -Command "Start-Process 'mitmdump' -ArgumentList '--mode regular@8080 --listen-host 127.0.0.1 --ssl-insecure -s mitm_interceptor.py' -NoNewWindow -PassThru"


exit
