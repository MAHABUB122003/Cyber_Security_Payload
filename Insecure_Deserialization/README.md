# Insecure Deserialization

Deserialization of untrusted data → remote code execution (RCE) in Java, PHP, .NET, Python, Ruby. Found in cookies, session stores, request bodies, and API parameters. When it hits, it's Critical.

## Where to look
| Place | Format |
|-------|--------|
| Java sessions / cookies | `rO0AB...` (java.io.Serializable base64), `aced0005` hex |
| Java (older) app request body | `ser`, `bin`, `raw` |
| PHP session / param | `O:8:"MyClass":2:{...}` (serialized object) |
| .NET ViewState | base64 gzip, `__VIEWSTATE` (needs keys for full RCE) |
| Python bottle/flask | `!pickle` (pickle protocol) |
| Ruby | `\x04\x08o:` (Marshal format) |
| Node | `express-cookie-session` (JSON), serialized JSON objects |

## Priority
1. Detect the serialization format.
2. Fingerprint gadget classes on classpath.
3. Generate payload with ysoserial / PHPGGC / ysoserial.net / marshalsec.
4. Trigger deserialization at a sink (header, cookie, body param, viewstate).
5. OOB → netcat. If no reverse-shell possible, use **DNS ping** for blind confirmation.

## Files
- `php-object-injection.txt` — PHP serialization strings, magic-method chains, PHPGGC use
- `java-deserialization.txt` — ysoserial chains, detection bytes, blind DNS
- `pickle-net-ruby.txt` — Python pickle, .NET ViewState, Ruby Marshal

## Tools
| Tool | Purpose |
|------|---------|
| **ysoserial** | Java chains (CommonsCollections1-6+, Spring, Groovy, ...) |
| **ysoserial.net** | .NET chains (TextFormattingRunProperties, WindowsIdentity, etc.) |
| **PHPGGC** | PHP gadget chains (Laravel, Symfony, Monolog, Guzzle, ...) |
| marshalsec | marshalling-based Java chains |
| Deserialize guy / burp suite extensions | detect + decode serialized blobs |
| `serializationhunter` | automation of secrets/keys |