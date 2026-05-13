# 🚀 CORS Misconfiguration Payloads 2026

> Complete payload list for detecting and exploiting CORS misconfigurations in modern web applications.

---

## 📋 Payload List

```http
Origin: https://evil.com
Origin: https://evil.com.evil.com
Origin: https://evil.com.target.com
Origin: https://target.com.evil.com
Origin: https://evil.com@target.com
Origin: https://evil.com#target.com
Origin: https://evil.com/target.com
Origin: https://evil.com%2Etarget.com
Origin: https://evil.com%252Etarget.com
Origin: https://target.com.evil.com:8080
Origin: https://evil.com.target.com:8080
Origin: https://subdomain.target.com
Origin: https://target.com.attacker.com
Origin: https://attacker.com.target.com
Origin: https://target.com.任意
Origin: https://任意.target.com
Origin: null
Origin: https://null
Origin: http://null
Origin: file://
Origin: https://evil.com%00.target.com
Origin: https://target.com%00.evil.com
Origin: https://evil.com%09.target.com
Origin: https://target.com%09.evil.com
Origin: https://evil.com%0A.target.com
Origin: https://target.com%0A.evil.com
Origin: https://evil.com%0D.target.com
Origin: https://target.com%0D.evil.com
Origin: https://evil.com%20.target.com
Origin: https://target.com%20.evil.com
Origin: https://evil.com/target.com//
Origin: https://target.com.evil.com//
Origin: https://evil.com@target.com:443
Origin: https://target.com@evil.com:443
Origin: *
Origin: https://*.target.com
Origin: http://evil.com
Origin: https://evil.com:8080
Origin: https://evil.com?target.com
Origin: https://target.com.evil.com?q=test
Origin: https://evil.com.target.com/admin
Origin: https://target.com\@evil.com
Origin: https://target.com.evil.com%2Fpath
Origin: https://evil.com%5C.target.com
Origin: https://target.com%5C.evil.com
Origin: https://target.com.evil.com/admin
Origin: https://admin-target.com.evil.com
Origin: https://target.com.evil.com/api
Origin: https://api.target.com.evil.com
Origin: https://target.com.evil.com/graphql
Origin: https://target.com.evil.com/oauth
Origin: https://target.com.evil.com/webauthn
