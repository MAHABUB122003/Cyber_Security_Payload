# HOW TO TEST INFORMATION DISCLOSURE ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## The leak classes to hunt (all ways)
1. Version banners: Server header, X-Powered-By, error pages -> frame exploit candidates.
2. .env/.git/.svn/backup endpoints: files exposed directly.
3. Stack traces / debug grids: verbose error pages.
4. API docs: /swagger, /openapi.json, /redoc, graphql playground.
5. Directory listing: /uploads/, /logs/, /backups/ with Indexes on.
6. Metadata/tmp files: .DS_Store, .htaccess, web.config, composer.lock, package-lock.json, wp-config.php.bak.
7. Source maps: .js.map + React/Vue source -> bundle secrets + routes.
8. Git exposure: /.git/HEAD 200 -> dump repository (git-dumper), extract credentials/deploy keys.
9. Debug endpoints in prod: /actuator, /console, /status, /health with internals.
10. Default-examples pages: /example/, phpinfo.php, robots.txt, sitemap.xml (check them for gems).
11. Error-triggered leaks: craft bad input to force stack trace with DB creds/paths.
12. Search-engine indexed secrets (Google dorking) -- for recon only.

## Step-by-step on target
1. Gather all response headers + the first bytes of every page (banner collection).
2. Request the classic files (list in #2/#4/#8) with HEAD/GET; check HTTP codes.
3. Force errors: ?id=1'  /  /x.php?debug=1  /  malformed JSON -> see full stack.
4. Trigger "verbose" modes: ?_= , ?debug=true, ?type=json&include=error, spoofed Host.
5. Regex-scan JS bundles for things that should not be there (keys, internal URLs, tokens).
6. Automated: waybackurls + grep for .git, .env, .bak, config; nuclei with -t exposures.

## Worked examples (concrete)
```
curl -i "https://target.com/.env"
curl -i "https://target.com/.git/config"
curl -i "https://target.com/.git/HEAD"                      # 200 "ref: refs/heads/main" = git pwn
for f in .bak .old .orig .swp ~; do curl -s -o /dev/null -w "%{http_code} $f\n" "https://target.com/index.php$f"; done
curl -i "https://target.com/robots.txt"                     # look for /admin, /backup
curl -i "https://target.com/sitemap.xml"
curl -i "https://target.com/swagger/" /swagger-ui.html /v2/api-docs /openapi.json
curl -i "https://target.com/actuator/health" /actuator/env
curl -i "https://target.com/latest/index.js.map"            # source map
Force error leak:
curl -i "https://target.com/api/v1/users/`"                 # malformed JSON body
curl -i "https://target.com/id=1'"                          # SQLi-styled error
git dump the whole repo:
```
git-dumper https://target.com/.git ./dumped

## False positives & scope
- A banner or /robots.txt listing is INFO, not a bounty unless it leads somewhere real.
- Public source map that only contains public routes = nah.
- .env with REAL key + reachable = High. Same file empty = nothing.

## Reporting
Present: discovered file + a real downstream impact (key usable, DB reachable, admin paths).
