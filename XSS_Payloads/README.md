# XSS_Payloads (2026 edition, curated)

## File index

| File | Use |
|------|-----|
| `basic_payload_advanced2026.txt` | Daily driver: events, obfuscation, cookie-exfil, shortest payloads, 2026 trends |
| `xss-2026-ultimate-waf-bypass.txt` | 200+ event handlers + tag matrix for filter mapping |
| `xss-complete-2026-mega-collection.txt` | Mega archive: every sink/tag/technique + vendor-specific (validated before use) |
| `xss-custom-vectors.txt` | Custom/gadget payloads: template literals, CSS, JSON, framework, DOM |
| `xss-all-list.txt` | Classic RSnake mega-list (512KB) - archive, spray-on-target reference only |
| `blind-xss.txt` | Blind XSS: passive hunters, beacons, tool setup (suspenders for UXSS) |
| `svg-image-xss-payloads.txt` | SVG/image context - best when uploads/avatars/file-carrier XSS |
| `portswigger-xss-lab-solutions.txt` | Academy lab walkthroughs: every context class solved step-by-step |
| `dom-clobbering-mxss-2026.txt` | DOM clobbering + mutation XSS technique pack (sanitizer bypass) |
| `framework-matrix-2026.txt` | React/Vue/Angular/Svelte/HTMX sink cheatsheet |
| `Lab_XSS_Payloads/` | Bengali lab note pads (AngularJS, headers, JSONP, postMessage, WebSocket) |

## Sink -> source cheat (DOM XSS)
- `document.write()` / `document.writeln()`  <- `location.search|hash|document.referrer`
- `innerHTML` / `outerHTML` / `insertAdjacentHTML` <- won't run `<script>`; use `<img onerror>`
- `eval()`/`Function()`/`setTimeout(string)` <- breaks out of any string context
- `jQuery.attr('href'/'src')`, `$.html()`, `.append()` <- javascript: scheme
- `location`/`location.href`/`window.open` <- javascript: / data: sinks
- Angular `{{ }}`, Vue `{{ }}`, React `dangerouslySetInnerHTML` <- framework-specific (see matrix)

## Pre-flight checklist
1. Identify context: HTML body / attribute / JS string / JS URL / CSS / raw Angular/Vue.
2. Break out of the tightest delimiter, then drop `<svg/onload=alert(1)>` or `-alert(1)-`.
3. If classic fails: try mXSS/DOM-clobber pack, then filter-mapping via the mega-list.
4. Output context persistence: stored vs reflected vs DOM.
5. Automate: dalfox / XSStrike / you for the parameter; CookieCollector + XSS Hunter for blind.

## Tools
- dalfox (fast param scan), XSStrike (smart), xssor/sulfoxide for mXSS, Burp + Collaborator for blind.
- Blind: xsshunter.com style collector or self-host; see `blind-xss.txt`.