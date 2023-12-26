from typing import Generator, Optional, NamedTuple, List
import base64
import hashlib

import httpx
import dicttoxml
import xmltodict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

FIRMWARE_LIST_URL = "http://fota-cloud-dn.ospserver.net/firmware/{0}/{1}/version.xml"
NONCE_URL = "https://neofussvr.sslcs.cdngc.net/NF_DownloadGenerateNonce.do"
BINARY_INFO_URL = "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInform.do"
BINARY_FILE_URL = "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInitForMass.do"
BINARY_DOWNLOAD_URL = "http://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do"

KEY_1 = "vicopx7dqu06emacgpnpy8j8zwhduwlh"
KEY_2 = "9u7qab84rpc16gvk"

class Session(NamedTuple):
    encrypted_nonce : str
    session_id : str
    signature : str
    nonce : str

class FirmwareMeta(NamedTuple):
    firmware_changelog_url : Optional[str]
    device_display_name : str

class FirmwareFile(NamedTuple):
    path : str
    decrypt_key : str
    digest : str
    digest_type : str
    cipher : str
    size : int
    size_readable : str
    android_version : str
    firmware_version : str
    date : int

class FirmwareDetails(NamedTuple):
    files : List[FirmwareFile]
    meta : FirmwareMeta

# --------------------
#  METHODS
# --------------------

#
#   Gets latest firmware version for a model.
#
def do_get_firmware_version(
    region : str,
    model : str
) -> Optional[str]:
    req = httpx.request("GET", FIRMWARE_LIST_URL.format(region, model), 
        headers = _get_headers()
    )
    req.raise_for_status()
    # Parse XML.
    body = xmltodict.parse(req.text, dict_constructor = dict)
    latest = body["versioninfo"]["firmware"]["version"]["latest"]
    firmware_ver = latest if type(latest) is str else latest["#text"] # noqa: E721
    if firmware_ver:
        return _resolve_firmware_version(firmware_ver)
    return None

#
#   Initializes a new session.
#   Session must be renewed before each request.
#
def do_get_session() -> Session:
    req = httpx.request("POST", NONCE_URL, 
        headers = _get_headers()
    )
    req.raise_for_status()
    return _build_session(
        encrypted_nonce = req.headers.get("NONCE"),
        session_id = req.cookies.get("JSESSIONID") or ""
    )

#
#   Requests file and download information 
#   about a firmware version.
#
def do_binary_details(
    firmware_version : str, 
    region : str, 
    model : str,
    imei : int,
    ack : Session
) -> FirmwareDetails:
    req = httpx.request("POST", BINARY_INFO_URL, content = _get_binary_info_xml(
        firmware_version = firmware_version,
        region = region,
        model = model,
        imei = imei,
        nonce = ack.nonce,
    ), headers = _get_headers(ack))
    req.raise_for_status()
    # Parse XML.
    body = xmltodict.parse(
        req.text, dict_constructor = dict
    )["FUSMsg"]["FUSBody"].get("Put", {})
    if "BINARY_NAME" not in body:
        raise Exception(req.text)
    # If file extension ends with .enc4 that means 
    # it is using version 4 encryption, otherwise 2 (.enc2).
    ENCRYPT_VERSION = 4 if str(body["BINARY_NAME"]["Data"]).endswith("4") else 2
    # The firmware file is encrypted, so construct an decryption key for later use.
    decryption_key = None
    if ENCRYPT_VERSION == 2:
        decryption_key = hashlib.md5(f"{region}:{model}:{firmware_version}".encode()).digest().hex()
    else:
        decryption_key = hashlib.md5(
            "".join([
                firmware_version[ord(x) & 0xF] for x in body["LOGIC_VALUE_FACTORY"]["Data"]
            ]).encode()
        ).digest().hex()
    return \
        FirmwareDetails(
            files = [
                FirmwareFile(
                    path = body["MODEL_PATH"]["Data"] + body["BINARY_NAME"]["Data"],
                    decrypt_key = decryption_key,
                    digest = body["BINARY_CRC"]["Data"],
                    digest_type = "CRC32",
                    cipher = "AES_CBC",
                    size = int(body["BINARY_BYTE_SIZE"]["Data"]),
                    size_readable = "{:.2f} GB".format(
                        float(body["BINARY_BYTE_SIZE"]["Data"]) / 1024 / 1024 / 1024
                    ),
                    date = int(body["LAST_MODIFIED"]["Data"]),
                    android_version = body["CURRENT_OS_VERSION"]["Data"].replace("(Android ", " ("),
                    firmware_version = firmware_version
                )
            ],
            meta = FirmwareMeta(
                firmware_changelog_url = body["DESCRIPTION"]["Data"],
                device_display_name = body["DEVICE_MODEL_DISPLAYNAME"]["Data"]
            )
        )

#
#   Initializes the download in the server
#   before downloading firmware file.
#
#   filepath:
#        Path of the firmware file in the server, can be obtained 
#        from do_binary_details(). The value looks like this:
#        "/neofus/9/SM-N920C_1_20220819152351_1eub6wdeqb_fac.zip.enc4"
#
def do_binary_init(
    filepath : str, 
    ack : Session
) -> Session:
    req = httpx.request("POST", BINARY_FILE_URL, content = _get_binary_init_xml(
        filename = filepath.split("/")[-1],
        nonce = ack.nonce
    ), headers = _get_headers(ack))
    req.raise_for_status()
    # Refresh session with new nonce.
    return _build_session(
        encrypted_nonce = req.headers["NONCE"],
        session_id = req.cookies.get("JSESSIONID", ack.session_id)
    )

#
#   Start downloading the file.
#
#   filepath:
#        Path of the firmware file in the server, can be obtained 
#        from do_binary_details(). The value looks like this:
#        "/neofus/9/SM-N920C_1_20220819152351_1eub6wdeqb_fac.zip.enc4"
#
def do_binary_download(
    filepath : str,
    ack : Session,
    decrypt_key : Optional[bytes] = None
) -> Generator[bytes, None, None]:
    cipher = None
    if decrypt_key:
        cipher = AES.new(decrypt_key, AES.MODE_ECB)
    with httpx.stream("GET", BINARY_DOWNLOAD_URL + "?file=" + filepath,
        headers = _get_headers(ack)
    ) as req:
        req.raise_for_status()
        current = b""
        for i in req.iter_bytes(1024):
            yield current
            current = i
        if cipher:
            yield unpad(current)
        else:
            yield current

# --------------------
#  PRIVATE
# --------------------

#
#   Gets HTTP headers for a given session.
#   For requesting a nonce, session is not required.
#
#   This is automatically called in other methods, 
#   so you don't have to call this manually.
#
def _get_headers(ack_session : Optional[Session] = None):
    if not ack_session:
        return {
            "Authorization": 'FUS nonce="", signature="", nc="", type="", realm="", newauth="1"',
            "User-Agent": "Kies2.0_FUS"
        }
    else:
        return {
            "Authorization": 'FUS nonce="{0}", signature="{1}", nc="", type="", realm="", newauth="1"'.format( # noqa: E501
                ack_session.encrypted_nonce,
                ack_session.signature
            ),
            "User-Agent": "Kies2.0_FUS",
            "Cookie": f"JSESSIONID={ack_session.session_id}"
        }

#
#   Constructs a XML payload with given firmware version for requesting
#   information about that specific firmware.
#
#   firmware_version, region, model:
#        Self-explanatory.
#
#   nonce:
#        Decrypted session nonce. The server doesn't allow sessions
#        to be reused more than once, so grab a new one with do_get_session().
#
#   This is automatically called in other methods, 
#   so you don't have to call this manually.
#
def _get_binary_info_xml(*,
    firmware_version : str, 
    region : str, 
    model : str, 
    nonce : str,
    imei : int
):
    logic_check = "".join([firmware_version[ord(x) & 0xF] for x in nonce])
    return dicttoxml.dicttoxml({
        "FUSMsg": {
            "FUSHdr": {"ProtoVer": "1.0"}, 
            "FUSBody": {
                "Put": {
                    "ACCESS_MODE": {"Data": "2"},
                    "BINARY_NATURE": {"Data": "1"},
                    "CLIENT_PRODUCT": {"Data": "Smart Switch"},
                    "CLIENT_VERSION": {"Data": "4.3.23123_1"},
                    "DEVICE_IMEI_PUSH": {"Data": str(imei)},
                    "DEVICE_FW_VERSION": {"Data": firmware_version},
                    "DEVICE_LOCAL_CODE": {"Data": region},
                    "DEVICE_MODEL_NAME": {"Data": model},
                    "LOGIC_CHECK": {"Data": logic_check}
                }
            }
        }
    }, attr_type = False, root = False)

#
#   Constructs a XML payload with given firmware path for
#   verifying the download token before starting to download the
#   firmware file.
#
#   filename:
#        Name of the firmware file in the server, can be obtained 
#        from do_binary_details(). The value looks like this:
#        "SM-N920C_1_20220819152351_1eub6wdeqb_fac.zip.enc4" (remove the path)
#
#   nonce:
#        Decrypted session nonce. The server doesn't allow sessions
#        to be reused more than once, so grab a new one with do_get_session().
#
#   This is automatically called in other methods, 
#   so you don't have to call this manually.
#
def _get_binary_init_xml(*,
    filename : str,
    nonce : str
):
    filename_logic = filename.split(".")[0][-16:]
    logic_check = "".join([filename_logic[ord(x) & 0xF] for x in nonce])
    return dicttoxml.dicttoxml({
        "FUSMsg": {
            "FUSHdr": {"ProtoVer": "1.0"}, 
            "FUSBody": {
                "Put": {
                    "BINARY_FILE_NAME": {"Data": filename},
                    "LOGIC_CHECK": {"Data": logic_check}
                }
            }
        }
    }, attr_type = False, root = False)

#
#   Creates a session.
#
#   Nonce is an encrypted value, so it must be decrypted
#   before to work with later endpoints.
#
#   This is automatically called in other methods, 
#   so you don't have to call this manually.
#
def _build_session(
    encrypted_nonce : str, 
    session_id : str
) -> Session:
    # Decrypt nonce value.
    cipher = AES.new(
        key = KEY_1.encode(), 
        mode = AES.MODE_CBC, 
        iv = KEY_1.encode()[:16]
    )
    actual_nonce : bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_nonce)), AES.block_size)
    # Create a signature key to encrypt the nonce.
    sigkey : str = "".join(map(lambda i: KEY_1[actual_nonce[i] % 16], range(16))) + KEY_2
    cipher = AES.new(
        key = sigkey.encode(), 
        mode = AES.MODE_CBC, 
        iv = sigkey.encode()[:16]
    )
    signature : bytes = cipher.encrypt(pad(actual_nonce, AES.block_size))
    # Collect all values together.
    return Session(
        encrypted_nonce = encrypted_nonce,
        session_id = session_id,
        signature = base64.b64encode(signature).decode(),
        nonce = actual_nonce.decode()
    )

#
#   Add missing parts of firmare version string
#   which is required for other endpoints.
#
#   This is automatically called in other methods, 
#   so you don't have to call this manually.
#
def _resolve_firmware_version(firmware: str) -> str:
    if firmware:
        f = firmware.split("/")
        if len(f) == 3:
            f.append(f[0])
        if f[2] == "":
            f[2] = f[0]
        return "/".join(f)