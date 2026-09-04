# WPScan Cheat Sheet (WordPress Scanner)
> **Author:** MD MAHABUBUR RAHMAN

WPScan is the standard tool for WordPress security testing. Free in CLI.

## Install
```
gem install wpscan
# or
docker run -it --rm wpscanteam/wpscan --url https://target.com
```

## Basic scan
```
wpscan --url https://target.com
```

## Enumerate everything useful
```
# u = users, vp = vulnerable plugins, vt = vulnerable themes, cb = config backups
wpscan --url https://target.com --enumerate u,vp,vt,cb

# also enumerate timthumb, db exports, dbs
wpscan --url https://target.com --enumerate u,vp,vt,tt,dbe,cb
```

## Detect all plugins aggressively (slow but finds hidden plugins)
```
wpscan --url https://target.com --enumerate vp --plugins-detection aggressive --plugins-version-detection aggressive
```

## Need valid API token (free) to show WPVulnDB CVEs
```
wpscan --url https://target.com --api-token YOUR_TOKEN --enumerate vp
# without a token you will see *No WPVulnDB API token given*
```

## Disable rate limiting / throttle
```
# Email-based throttle (free WPScan account):
wpscan --url https://target.com --random-user-agent --throttle 200

# Or use new non-throttling method if you have a plan:
wpscan --url https://target.com --disable-throttle
```

## Brute force
```
wpscan --url https://target.com --passwords /path/to/passwords.txt --usernames admin

# on xmlrpc (much faster - multicall)
wpscan --url https://target.com --passwords rockyou.txt --usernames admin --force
```

## Headers / fingerprinting
```
wpscan --url https://target.com --headers "Cookie: foo=bar"
wpscan --url https://target.com --api-token TOKEN --detection-mode aggressive
```

## Save output
```
wpscan --url https://target.com --enumerate u,vp,vt --format cli-no-color > wpscan.txt
wpscan --url https://target.com --format json -o scan.json
```

## Common flags explained
| Flag | Meaning |
|------|---------|
| `--enumerate u,ap,at,cb,dbe` | users, all plugins, all themes, config backups, db exports |
| `-e vp,vt` | only vulnerable plugins/themes |
| `--plugins-detection aggressive` | look for more plugin files (slower) |
| `--password-attack xmlrpc` | brute force via xmlrpc multicall (use `--force`) |
| `--api-token` | free token @ wpscan.com to get CVE data |
| `--random-user-agent` | avoid simple bot blocks |

## After wpscan finishes
- Take the listed **vulnerable plugins** + versions → cross-check in this repo: `wp-known-plugin-exploits.txt`
- Take **usernames** → try `admin/<user>:password` combos, then xmlrpc brute force.
- Take **IDs** (user id like `[!] user 'admin' ... ID: 1`) → test author enum via `?author=1`.
