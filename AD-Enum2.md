### Domain Enumertation

```
Get-Domain (Powerview)
Get-ADDomain (ActiveDirectory )
```
### Get Objects of another domain 
```
Get-domain -domain tech.local
Get-Addomain -identity tech.lcoal
```

### Get SID 
```
Get-domainSID (Get-ADDomain).DoaminSID
```
### Domain Enumeration 
```
Get-DomainPolicyData(Get-domainPolicyData).systemaccess
```
### Get domain policy for another domain 
```
(Get-domainPolicydata -domain tech.local).systemaccess
```
### Get domian controller for the curret domain 
```
Get-domaincontroller
```
### User details 
```
Get-DomainUser
Get-DomainUser –Identity studentuser1
(powerview_)
Get-ADUser –Filter * –Properties *
Get-ADUser –Identity studentuser1 –Properties
```
```
Get-DomainUser –Identity studentuser1 –Properties *
Get-DomainUser –Properties pwdlastset
(powerview)
Get-ADUser –Filter * –Properties * | select –First 1 | Get-Member –MemberType *Property | select Name
Get-ADUser –Filter * –Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```
