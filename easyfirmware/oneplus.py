from typing import List, Dict, Any, NamedTuple

import httpx
from bs4 import BeautifulSoup

class FirmwareMeta(NamedTuple):
    changelog : str
    device : str
    device_display_name : str

class FirmwareFile(NamedTuple):
    url : str
    digest : str
    digest_type : str
    size_readable : str
    firmware_version : str
    date : int

class FirmwareDetails(NamedTuple):
    files : List[FirmwareFile]
    meta : FirmwareMeta

# --------------------
#  METHODS
# --------------------

#
#   Gets a list of firmwares.
#
def do_get_firmwares() -> List[Dict[str, Any]]:
    req = httpx.request("POST", "https://sow-cms-sg.oneplus.com/oppo-server/OnePlus/docDetails", 
    json = {
        "articleId": "2096329",
        "queryId": None,
        "language": "en-US",
        "area": "en",
        "articleIndex": "1",
        "region": "en",
        "isoLanguageCode": "en-US",
        "sourceRoute": "1",
        "brandCode":"12"
    }, headers = { 
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" 
    })
    content = BeautifulSoup(req.json()["data"]["content"], "lxml")
    result = []
    is_first_row = True
    for i in content.find_all("tr"):
        if is_first_row:
            is_first_row = False
            continue
        result.append(
            FirmwareDetails(
                files = [
                    FirmwareFile(
                        url = i.contents[13].find("a")["href"],
                        digest = i.contents[11].text,
                        digest_type = "MD5",
                        size_readable = i.contents[9].text,
                        firmware_version = i.contents[5].text,
                        date = i.contents[7].text
                    )
                ],
                meta = FirmwareMeta(
                    changelog = i.contents[3].get_text(strip = True),
                    device = i.contents[13].find("a")["href"].split("/")[-1].split("Oxygen")[0],
                    device_display_name = i.contents[1].text
                )
            )
        )
    return result

# See also: https://onepluscommunityserver.com/