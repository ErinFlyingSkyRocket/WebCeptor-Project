Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd.exe /c start /b mitmdump --mode regular@8080 --listen-host 127.0.0.1 --ssl-insecure -s mitm_interceptor.py", 0, False
