Blind fuzz
```
wfuzz -c -w ./lfi2.txt --hw 0 http://10.10.10.10/nav.php?page=../../../../../../../FUZZ


Seclist -> SecLists/Fuzzing/LFI/LFI-Jhaddix.txt

```
Wfuzz
```
wfuzz -c -x file,/opt/Seclist/Discovery/WEb-Content/raft-large-files.txt --hc 404 "<url>"
url="<http://<ip>/console/file.php?FUZZ=../../../../../../../etc/passwd"
wfuzz -c -x file,/opt/Seclist/Discovery/WEb-Content/burp-parameter-names.txt --hh 0 "<url>
```
gobuster
````
 sudo gobuster dir -u http://192.168.194.122:49673/ -w  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
sudo gobuster dir -u https://192.168.194.122:49673/ -w  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -k
sudo gobuster dir -u https://192.168.174.10:9090/ -w  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -k --exclude-length 43264 
```
FFUF
```
ffuf -w  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u https://192.168.174.10:9090/FUZZ
```
