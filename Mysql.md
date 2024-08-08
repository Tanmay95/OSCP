### Mysql commands:
```
show databases;
use <database>;
connect <database>;
show tables;
describe <table_name>;
show columns from <table>;
```
```
mysql -u root -h 127.0.0.1 -e 'show databases;'
```
https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql

## Privilege Escaltion 
```
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | grep "user"
systemctl status mysql 2>/dev/null | grep -o ".\{0,0\}user.\{0,50\}" | cut -d '=' -f2 | cut -d ' ' -f1
```
