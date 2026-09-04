# Prototype Pollution

Prototype pollution happens when user input can set properties on the global `Object.prototype` (JavaScript). It leads to:
- **Client-side**: XSS via `src`/`href`/`innerHTML` sinks when apps read polluted properties like `location`, `src`, `srcdoc`.
- **Server-side**: SSRF, RCE, auth bypass, DoS — depends on how the server uses object defaults (e.g. `options.host`, `child_process` opts).

## Detection (client-side)
In the browser console, payloads that add a property to `Object.prototype`:
```js
__proto__.polluted = true

// via JSON.parse recursion (jQuery/deepmerge/lodash.defaultsDeep style)
JSON.parse('{"__proto__":{"polluted":true}}')
```
Then confirm:
```js
({}).polluted === true   // true → POLLUTED
```
Check for pollution with a unique property name not present before:
```js
Object.prototype.myAwesomeTestProp === true
```

## Priority attack path
1. Find a merging/settling gadget (`$.extend`, `$.merge`, `_.merge`, `_.defaultsDeep`, `object-assign-deep`, `deepmerge`, `set-value`) reachable from user input (query string, JSON body, path params).
2. Pollute a **known gadget property** (e.g. `innerHTML`, `src`, `fetch-options.host`, `shell`, `NODE_OPTIONS`).
3. Trigger the sink that reads that property to convert pollution → XSS / RCE.

## Client-side gadgets (very reliable in bug bounty)
- Polluting `innerHTML` then the app renders an element with `v-html`/template → XSS
- Polluting `src` on an `<img>` element the app creates with defaults → XSS via `file://`/`data:` or external
- Polluting `srcdoc` on iframes created with `{}` defaults → XSS
- AngularJS/Vue templates reading `constructor.prototype`
- DOMPurify bypass chains (pollute `ALLOWED_ATTR` / `ALLOWED_TAGS` on the config object)

## Server-side gadgets (higher severity)
- `child_process.exec(options)` → pollute `shell: "/proc/self/exe"` + `argv0` + `NODE_OPTIONS` → RCE
- `http.request options.host` pollution → SSRF
- `path.join` + `error.path` gadget → file read
- Prisma/sequelize where-clause pollution → auth bypass
- `ejs`/`pug` template options pollution (`client`, `escapeFunction`, `outputFunctionName`) → RCE

## Files
- `client-side-prototype-pollution.txt` — detection + XSS gadgets
- `server-side-prototype-pollution.txt` — RCE/SSRF chains + JSON payloads