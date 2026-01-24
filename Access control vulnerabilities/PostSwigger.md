Url: https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter
use BurpSuite
```
Cookie: Admin=true; session=fqp8yYIRTldGT5v9M2wvHvMALbkDz6kP
Observe that the response sets the cookie Admin=false. Change it to Admin=true.
```
