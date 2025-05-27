# Main script, used for testing for now
#
# at the moment, it will just take a given file and pull it's 
# MD5, SHA256, and SHA1 hashes

import hashlib
import sys
import os

# I'll condense the open in binary parts into it's own function - done
# Condensed it all into one function

# Returns binary data from a given file and given hash functions
def get_hash(file_path, hash_func):
    # hash object
    hash_object = hash_func()

    # open file in binary mode
    with open(file_path, "rb") as f:
        # read file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_object.update(byte_block)
    f.close()
    # return the hex representation of the hash
    return hash_object.hexdigest()

# main function
def main():
    # check for if the user provided a real file
    if len(sys.argv) != 2:
        print("Usage: python main.py <file>")
        sys.exit(1)
    # check if the file exists
    if not os.path.isfile(sys.argv[1]):
        print("File does not exist")
        sys.exit(1)
    # file path
    path = sys.argv[1]
    # file name and size
    name = os.path.basename(path)
    size = os.path.getsize(path)
    # hashes
    md5 = get_hash(path, hashlib.md5)
    sha1 = get_hash(path, hashlib.sha1)
    sha256 = get_hash(path, hashlib.sha256)
    # print the results
    print(f"File: {name}")
    print(f"Size: {size} bytes")
    print(f"MD5: {md5}")
    print(f"SHA1: {sha1}")
    print(f"SHA256: {sha256}")
    # return 0
    return 0

main()