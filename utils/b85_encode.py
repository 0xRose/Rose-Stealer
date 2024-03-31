from base64 import b85encode
from sys import argv

if len(argv) == 2:
    print(b85encode(argv[1].encode("utf-8")).hex())
else:
    print(
        "Please specify the data to be base85 encoded like this.\n'python b85_encode.py 127.0.0.1'"
    )
