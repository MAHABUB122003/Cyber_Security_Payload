# XPath Injection
> **Author:** MD MAHABUBUR RAHMAN

XPath queries on XML data (config files, SOAP, legacy apps) are injectable like SQL — auth bypass and data extraction without a database.

## Where
- Old Java/.NET apps with `.xml` configs
- SOAP/XML endpoints reading nodes by input
- Apps that expose "Preferences", "Search", "Doc IDs" built from XPath

## Priority
1. Auth bypass: `//user[username='...' and pass='...']`
2. Extract all: `*`, `|`, `..`
3. Blind boolean extraction

## Files
- `xpath-injection-payloads.txt`

## Quick detection
```
' or '1'='1
' or '1'='1' or 'x'='y
* | *
string(//*) 
```
If the endpoint returns ALL records instead of one → injectable.
To confirm XPath (vs SQL): error messages, `//` path syntax, or `count(//*)` behavior.
