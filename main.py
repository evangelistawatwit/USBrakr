# Main script, used for testing for now
#
# takes a given file and pull its 
# MD5, SHA256, and SHA1 hashes

import hashlib
import sys
import os
import csv
from zipfile import ZipFile
from urllib.request import urlopen
import subprocess
import psutil

# setup and install wget if not already installed
try:
    import wget, pandas as pd
except ImportError:
    print("wget not found, installing...")
    os.system('pip install wget pandas')
    import wget, pandas as pd

# predownloaded CSV file for compatibility testing
csv_list = "full.csv"

def active_cnx():
    try:
        urlopen('http://www.google.com/', timeout=5)
        return True
    except:
        return False

def update():
    # once run, wait indefintely for internet connection
    while True:
        if active_cnx() is True:
            break
        else:
            print("No active internet connection.")

    url = 'https://bazaar.abuse.ch/export/csv/full/'
    # download the zip file
    file_name = wget.download(url)
    # extract the zip file
    with ZipFile(file_name, 'r') as zip_file:
        zip_file.extractall()
        print("Files extracted successfully.")
    #remove the zip file after extraction
    os.remove(file_name)
    csv_list = 'full.csv'

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
    return('"' + hash_object.hexdigest() + '"')

# Returns the gievn file's hash if it exists in the given CSV file
def compare_to_csv(file_path):
    # read the CSV file
    flagged_hashes = []
    mb_list = pd.read_csv(csv_list, on_bad_lines='skip', skiprows=[0,1,2,3,4,5,6,7,8], usecols=[1,2,3,4], header=None)
    # get the hash of the file
    md5 = get_hash(file_path, hashlib.md5)
    sha1 = get_hash(file_path, hashlib.sha1)
    sha256 = get_hash(file_path, hashlib.sha256)
    
    # check if the hashes are in the CSV file
    if md5 in mb_list[2].values:
        print(f"MD5 hash {md5} found in CSV file.")
        flagged_hashes.append(md5)
    else:
        print(f"MD5 hash {md5} not found in CSV file.")
    
    if sha1 in mb_list[3].values:
        print(f"SHA1 hash {sha1} found in CSV file.")
        flagged_hashes.append(sha1)
    else:
        print(f"SHA1 hash {sha1} not found in CSV file.")
    
    if sha256 in mb_list[1].values:
        print(f"SHA256 hash {sha256} found in CSV file.")
        flagged_hashes.append(sha256)
    else:
        print(f"SHA256 hash {sha256} not found in CSV file.")

    # if any of the hashes are found, return the flagged hashes
    if flagged_hashes:
        return flagged_hashes
    else:
        print("No matching hashes found in CSV file.")
        return None

# formats a given drive with a partition of 512 megabytes, leaving the rest unallocated until needed
# for a windows system
def format_drive(drive_path):
    # check if the drive exists
    if not drive_path.endswith(':'):
        drive_path += ':'
    if drive_path[0] not in ['C']:
        if not os.path.exists(drive_path):
            print(f"Drive {drive_path} does not exist.")
            return False
    
    # format the drive with 512 megabytes
        os.system(f'format {drive_path} /FS:NTFS /Q /V:USBDrive /X /Y')
        return True
    else:
        print(f"Drive {drive_path} is a system drive and cannot be formatted.")
        return False

# returns a list of all drives on the system
def get_drives():
    # get all drives
    drives = [f"{d}:" for d in "ABDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:")]
    return drives

# appends a partition (default 512 kilobytes) to the given drive
# on a windows system
def append_partition(drive_path, partition_size=512 * 1024):
    # check if the drive exists
    if not drive_path.endswith(':'):
        drive_path += ':'
    if drive_path[0] not in ['C']:
        if not os.path.exists(drive_path):
            print(f"Drive {drive_path} does not exist.")
            return False
    elif drive_path[0] in ['C']:
        print(f"Drive {drive_path} is a system drive and cannot be modified.")
        return False
    
    # grabs the disk number of the drive
    try:
        drive_letter = drive_path[0]
        ps_cmd = (
            f"Get-Partition -DriveLetter {drive_letter} | "
            "Get-Disk | "
            "Select-Object -ExpandProperty Number"
        )
        output = subprocess.check_output(
            ["powershell", "-Command", ps_cmd],
            universal_newlines=True
        )
        disk_number = output.strip()
        if disk_number.isdigit():
            print(f"Disk number for drive {drive_path} is {disk_number}.")
        else:
            print(f"Could not determine disk number for drive {drive_path}.")
            return False
    except Exception as e:
        print(f"Error determining disk number: {e}")
        return False
    # create a new partition of the given size
    try:
        partition_cmd = (
            f"New-Partition -DiskNumber {disk_number} -Size {partition_size} "
            "-AssignDriveLetter | "
            "Format-Volume -FileSystem NTFS -NewFileSystemLabel 'USBDrive' -Confirm:$false"
        )
        subprocess.run(["powershell", "-Command", partition_cmd], check=True)
        print(f"Partition of size {partition_size} bytes created on drive {drive_path}.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error creating partition: {e}")
        return False


# gets file size
def get_file_size(file_path):
    if os.path.isfile(file_path):
        return os.path.getsize(file_path)
    else:
        print(f"File {file_path} does not exist.")
        return None
    



# main function
def main():
    # format the drive if the user wants to
    print("Do you want to format the drive? (y/N)")
    format_drive_choice = input().strip().lower()
    if format_drive_choice == 'y':
        print("Available drives:")
        drives = get_drives()
        for drive in drives:
            print(drive)
        print("Enter the USB drive letter to format (e.g., E, F):")
        drive_letter = input().strip().upper()
        if input(f"Are you sure you want to format drive {drive_letter}? This will erase all data on the drive. (y/N) ").strip().lower() == 'y':
            if format_drive(drive_letter):
                print(f"Drive {drive_letter} formatted successfully.")
        else:
            print("Drive formatting cancelled.")
    else:
        print("Skipping drive formatting.")
    # update the CSV file if the user already has it
    if active_cnx() is True:
        if os.path.isfile(csv_list):
            print(f"CSV file {csv_list} already exists. Do you want to update it? (y/N)")
            update_choice = input().strip().lower()
            if update_choice == 'y':
                update()
            else:
                print("Skipping CSV file update.")
        else:
            print(f"CSV file {csv_list} does not exist. Downloading it...")
            update()
    else:
        print("No active internet connection. Aborting.")
        sys.exit(1)
    # get the file path
    print("Enter the file path to get the hashes:")
    path = input().strip()
    # check if the file path is provided
    if not path:
        print("No file path provided. Exiting.")
        sys.exit(1)
    # check if the file exists
    if not os.path.isfile(path):
        print(f"File {path} does not exist. Exiting.")
        sys.exit(1)
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
    print(f"SHA256: {sha256} \n")

    # compare the hashes to the CSV file
    results = compare_to_csv(path)

    # append a partition to the drive if all 3 hashes match in results, with user confirmation
    # also copies the file to the new partition to isloate it, deleting the original file
    if results:
        print("All hashes matched in the CSV file. Do you want to append a partition to the drive? (y/n)")
        append_partition_choice = input().strip().lower()
        if append_partition_choice == 'y':
            print("Available drives:")
            drives = get_drives()
            for drive in drives:
                print(drive)
            print("Enter the USB drive letter to append the partition (e.g., E, F):")
            drive_letter = input().strip().upper()
            if append_partition(drive_letter, size + 512 * 1024 * 1024):
                # copy the file to the new partition (next letter after the drive letter)
                new_drive_letter = chr(ord(drive_letter) + 1)
                new_file_path = f"{new_drive_letter}:/{name}"
                try:
                    os.makedirs(f"{new_drive_letter}:/", exist_ok=True)
                    with open(path, 'rb') as src_file:
                        with open(new_file_path, 'wb') as dest_file:
                            dest_file.write(src_file.read())
                    print(f"File copied to {new_file_path}.")
                    # delete the original file
                    os.remove(path)
                    print(f"Original file {path} deleted.")
                except Exception as e:
                    print(f"Error copying file: {e}")
                
            
        else:
            print("Skipping partition appending.")
    else:
        print("No matching hashes found in CSV file. Skipping partition appending.")
    


main()