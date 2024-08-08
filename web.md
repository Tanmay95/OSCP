### check for ssrf or RFI 
```
kali
sudo tcpdump icmp -i tun0

Webserver
python3 <webserver-url> -c "ping -c4 <attacker-ip>"
``` 
