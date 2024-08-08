### Forward RDP from internal host to Attacking Machine on port 1337.
ssh -L <LocalHost>:<Port>:<IP-To-Forward-From>:<Port> <User>@<IP>
ssh -L 127.0.0.1:1337:10.200.48.150:3389 root@10.200.48.200 -i id_rsa

### Forward remote port 80 to local port 80.
ssh atena@10.10.72.69 -L 80:127.0.0.1:80
ssh <User>@<IP> -L <Local-Port>127.0.0.1<Remote-Port>

### Dynamic SSH Port Forwarding
ssh -i <id_rsa> <User>@<IP> -D <Proxychains-Port>
ssh -i id_rsa errorcauser@10.10.254.201 -D 1080

Meterpreter port forward 
```
portfwd add -l <LocalPort> -p <RemotePort> -r <TargetIP>
portfwd add -l 3333 -p 3389 -r 10.10.10.5
Essentially as per the example command above we could connect to RDP on our local port in order to hit the remote port.
```

```
rdesktop 127.0.0.1:3333
```

xFreeRDP
```
xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share
```

## PORTS:
https://viperone.gitbook.io/pentest-everything/everything/ports
