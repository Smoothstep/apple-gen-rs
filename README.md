**WIP**

# Description

The following projects contain wrapper functions around apple-gen for:
1) Generating validation data
2) Encryption of io platform variables / IOPower variables
3) Generating anisette data (TBD)

There is also a native python module to give access to the rust library through PYO3, which builds wheels for your desired python version with maturin.

apple-auth-utils requires [apple-gen](https://github.com/Smoothstep/apple-gen) to build correctly. 

# Instructions

clone the repo and make sure to pull the submodules

`git clone --recursive https://github.com/Smoothstep/apple-gen-rs.git`

To build python wheels, maturin is needed:

`pip install maturin`

cd into apple-auth-py and execute the command (README).

# Status

This is only an early implementation, thus most code is subject to change.
For more information, refer to the apple-gen repository.

# Hints

Apple ID service & validation data:

- When registering with different machine data, it's adviced to not change the product name from your initial device as it could trigger an automatic block.
- For most variables, there are no validation checks, making it possible to use random inputs.

Only few inputs have been tested so far.

## Generating validation data in Python

Once the wheels are built with maturin and installed with pip (pip install [wheels] --force-reinstall), you should be able to call into the stub like so:

```
# Import necessary libraries
import uuid
import string
import random
import json
import apple_auth

# Function to generate a random UUID
def gen_uuid():
    random_uuid = uuid.uuid4()
    uuid_str = str(random_uuid).upper()
    return uuid_str

# Valid characters for generating serial
characters = string.ascii_uppercase + string.digits

# Function to generate validation data
def get_validation_data():
    # Generate random MAC address
    mac = [0x5c, 0xf7, random.randrange(0, 255), 0x00, 0x00, 0x0f]
    # Generate random UUIDs for boot and platform
    boot = gen_uuid()
    platform = gen_uuid()
    # Generate random serial number
    serial = "C02" + ''.join(random.choice(characters) for _ in range(5)) + "JK7M"
    # Generate random ROM address
    rom = [0x57, 0xD0, random.randrange(0, 255), 0x9D, 0xD6, 0x86]
    # Generate random MLB (Main Logic Board) serial
    mlb = "".join([random.choice(characters) for _ in range(17)])
    # Information dictionary
    info = {
        "rom": "".join(hex(c)[2:].zfill(2) for c in rom),
        "board_id": "Mac-27AD2F918AE68F65",
        "product_name": "MacPro7,1",
        "mac": ":".join(hex(c)[2:].zfill(2) for c in mac),
        "platform_serial": serial,
        "mlb": mlb,
        "root_disk_uuid": boot,
        "platform_uuid": platform
    }
    # Request validation data from apple_auth module and return it as bytes
    return bytes(apple_auth.IDS(json.dumps(info)).request_validation_data())
```
