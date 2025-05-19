# Main script, used for testing for now
#
# at the moment, it will just take a given file and pull it's 
# MD5, SHA256, and SHA1 hashes

import hashlib
import sys
import os

# I'll condense the open in binary parts into it's own function

# Returns the MD5 hash of a given file
def get_MD5(file_path):
    # hash object
    md5_hash = hashlib.md5()

    # open file in binary mode
    with open(file_path, "rb") as f:
        # read file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)

    # return the hex representation of the hash
    return md5_hash.hexdigest()

# Returns the SHA256 hash of a given file
def get_256(file_path):
    # hash object
    sha256_hash = hashlib.sha256()

    # open file in binary mode
    with open(file_path, "rb") as f:
        # read file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)