# Subdomain Takeover

A subdomain pointing at a cloud service (S3, GitHub Pages, Heroku, Netlify, Azure, Shopify, etc.) that no longer exists = **claim it and take over the subdomain**. Classic high-impact, low-effort bug.

## How it works
1. CNAME for `legacy.target.com` → `something.herokuapp.com` (or s3 bucket, github page...)
2. The cloud provider account/services you're pointed to is de-provisioned.
3. The cloud provider returns a "no such bucket / not found" page for that CNAME.
4. You register the missing resource with the same name → your content is now served on `legacy.target.com`.

## Priority fingerprints (when response says it's unclaimed)
| Provider | CNAME pattern | Claimed / Not claimed marker |
|----------|---------------|-------------------------------|
| AWS S3 | `<bucket>.s3.amazonaws.com` | `NoSuchBucket` error |
| Azure | `*.azurewebsites.net` | `404 Web Site not found` |
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here.` |
| Heroku | `*.herokuapp.com` | `No such app` |
| Netlify | `*.netlify.app` | `Not Found - Request ID` |
| Shopify | `*.shopify.com` | `Sorry, this shop is currently unavailable.` |
| Fastly | `*.fastly.net` | `Fastly error: unknown domain` |
| Cloudfront | `*.cloudfront.net` | `ERROR: The request could not be satisfied` |
| Pantheon | `*.pantheonsite.io` | `404 error unknown site` |
| Bitbucket | `*.bitbucket.io` | `Repository not found` |
| Surge.sh | `*.surge.sh` | `project not found` |
| WordPress.com | `*.wordpress.com` | `Do you want to register ...?` |

## Files
- `fingerprints.txt` — DNS + content checks

## Workflow
```bash
# 1. Find dangling subdomains
subfinder -d target.com -silent | while read d; do
  ip=$(dig +short "$d" CNAME | head -1)
  [ -n "$ip" ] && echo "$d -> $ip"
done

# 2. Check which return a claimable marker
curl -s https://<sub>/ -o /dev/null -w "%{http_code}"
curl -s https://<sub>/ | grep -i "no such\|not found\|doesn't exist"
```

## Tools
- **subjack** (CLI): `subjack -w subdomains.txt -t 100 -ssl -v -o results.txt`
- **tko-subs**: `./tko-subs -domains subdomains.txt -data providers-data.csv`
- **can-i-take-over-xyz** fingerprints db (refer to their readme)
- `dnsx -silent` for CNAME enumeration cheap

## Reporting
- Show the CNAME + the provider's "unclaimed" page + a claimed-fallback PoC (register the resource once, show you control the subdomain, then delete it).