```
{
  "host": {"hostname":"...", "os":"windows|linux", "timestamp":"..."},
  "processes": [
    {
      "pid": 1234,
      "ppid": 456,
      "name": "svchost.exe",
      "user": "NT AUTHORITY\\SYSTEM",
      "path": "C:\\Windows\\System32\\svchost.exe",
      "cmdline": "...",
      "start_time": "...",
      "sha256": "...",
      "signer": {"status":"valid|invalid|unsigned|unknown", "subject":"..."},
      "connections": [
        {"proto":"tcp", "local":"0.0.0.0:135", "remote":null, "state":"LISTEN"}
      ]
    }
  ]
}
```
