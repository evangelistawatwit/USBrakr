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
from datetime import datetime

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

# Returns the given file's hash if it exists in the given CSV file
def compare_to_csv(file_path):
    # read the CSV file
    mb_list = pd.read_csv(
        csv_list, 
        on_bad_lines='skip', 
        skiprows=[0,1,2,3,4,5,6,7,8], 
        usecols=[0,1,2,3,4,5,6,7,8,9,10,11,12], 
        header=None)
    flagged_rows = []
    # map hash functions to their CSV columns
    hash_reqs = {
        "MD5": (hashlib.md5, 2),
        "SHA1": (hashlib.sha1, 3),
        "SHA256": (hashlib.sha256, 1)
    }
    # get the hash of the file
    for name, (hash_func, column_name) in hash_reqs.items():
        hash_value = get_hash(file_path, hash_func)
        print("File: " + file_path)
        # Find rows where hash matches
        matches = mb_list[mb_list[column_name] == hash_value]

        if not matches.empty:
            print(f"{name} hash {hash_value} found in CSV file.")
            # Add all matched rows (as dicts) to list
            for _, row in matches.iterrows():
                flagged_rows.append(row.to_dict())
        else:
            print(f"{name} hash {hash_value} not found in CSV file.")

    if flagged_rows:
        return flagged_rows
    else:
        print("No matching hashes for " + file_path + " found in CSV file.")
        return None
    
# generate an html report as a string, parse data from each row
def generate_html_report(flagged_rows):
    html = """
    <html>
    <head><title>Malware Scan Report</title></head>
    <body>
    <h1>Malware Scan Results</h1>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr>
            <th>First Seen</th>
            <th>SHA256 Hash</th>
            <th>MD5 Hash</th>
            <th>SHA1 Hash</th>
            <th>File Name</th>
            <th>File Type Guess</th>
            <th>Signature</th>
        </tr>
    """

    for row in flagged_rows:
        html += f"""
        <tr>
            <td>{row.get('first_seen_utc', '')}</td>
            <td>{row.get('sha256_hash', '')}</td>
            <td>{row.get('md5_hash', '')}</td>
            <td>{row.get('sha1_hash', '')}</td>
            <td>{row.get('file_name', '')}</td>
            <td>{row.get('file_type_guess', '')}</td>
            <td>{row.get('signature', '')}</td>
        </tr>
        """

    html += """
    </table>
    </body>
    </html>
    """
    return html

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
    
# export log file detailing threat report to a .txt file
def export_log(flagged_hashes, scanned_files, choices=["n", "", "n", "", "n", ""]):
    file_name = "Log_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"
    with open(file_name, 'w') as log_file:
        log_file.write("User Choices:\n\n")
        log_file.write("Format Drive?: " + str(choices[0]) + '\n')
        if choices[0] == 'y':
            log_file.write("Drive Letter: " + choices[1] + '\n')
        log_file.write("Update CSV?: " + str(choices[2]) + '\n')
        log_file.write("File Path: " + choices[3] + "\n\n")
        log_file.write("Append Partition?: " + choices[4] + '\n')
        if choices[4] == 'y':
            log_file.write("Drive Letter?: " + choices[5] + '\n\n')
        else:
            log_file.write('\n')

        log_file.write("Malware Scan Report\n\n")
        log_file.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        log_file.write(f"Scanned Files:\n")
        for file in scanned_files:
            if(os.path.isdir(file)):
                continue
            log_file.write(f"{file}")
            log_file.write(f"Size: {get_file_size(file)} bytes\n")
            log_file.write(f"MD5: {get_hash(file, hashlib.md5)}\n")
            log_file.write(f"SHA1: {get_hash(file, hashlib.sha1)}\n")
            log_file.write(f"SHA256: {get_hash(file, hashlib.sha256)}\n\n")
        
        log_file.write("\n")
        log_file.write("Hash Results:\n")
        if flagged_hashes:
            log_file.write("Flagged Hashes: \n")
            for row in flagged_hashes:
                log_file.write(f"{row}\n")
        else:
            log_file.write("No flagged hashes found.\n\n")

def file_lister(path):
    if os.path.isdir(path):
        files = [os.path.join(path, file) for file in os.listdir(path) if os.path.isfile(os.path.join(path, file))]
        print("Directory detected. The following files will be scanned:")
        for file in files:
            print(file)
    else:
        files = [path]
    return files


# main function
def main():
    # format the drive if the user wants to
    print("Do you want to format the drive? (y/N)")
    format_drive_choice = input().strip().lower()
    choices = [format_drive_choice]
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
    choices.append(drive_letter if format_drive_choice == 'y' else "")
    # update the CSV file if the user already has it
    if active_cnx() is True:
        if os.path.isfile(csv_list):
            print(f"CSV file {csv_list} already exists. Do you want to update it? (y/N)")
            update_choice = input().strip().lower()
            choices.append('y' if update_choice == 'y' else 'n')
            if update_choice == 'y':
                update()
            else:
                print("Skipping CSV file update.")
        else:
            print(f"CSV file {csv_list} does not exist. Downloading it...")
            update()
    else:
        print("No active internet connection. Skipping...")
        choices.append('n')
    
    # get the file path
    print("Enter the file path to get the hashes:")
    path = input().strip()
    choices.append(path)

    # check if the file path is provided
    if not path:
        print("No file path provided. Exiting.")
        sys.exit(1)
    # check if the path exists
    if not os.path.exists(path):
        print(f"Path {path} does not exist. Exiting.")
        sys.exit(1)

    # makes list of files
    files = file_lister(path)
    # dictionary for hashes
    hash_dict = {}
    results = []
    flagged_files = []
    # loop to get all 3 hash types per file
    # and size/name
    for file in files:
        if(os.path.isdir(file)):
            continue
        name = os.path.basename(file)
        size = get_file_size(file)
        md5 = get_hash(file, hashlib.md5)
        sha1 = get_hash(file, hashlib.sha1)
        sha256 = get_hash(file, hashlib.sha256)
        hash_dict[name] = {"name": name, "size": size, "md5": md5, "sha1": sha1, "sha256": sha256}
        print(f"File: {name}")
        print(f"Size: {size} bytes")
        print(f"MD5: {md5}")
        print(f"SHA1: {sha1}")
        print(f"SHA256: {sha256}\n")


    # compare the hashes to the CSV file
    for file in files:
        if compare_to_csv(file):
            results.append(compare_to_csv(file))
            flagged_files.append(file)

    # append a partition to the drive if all 3 hashes match in results, with user confirmation
    # also copies the file to the new partition to isloate it, deleting the original file
    if flagged_files:
        #export html file to working directory
        # I might have broken this function by changing this to a full directory scanner -Will
        # html_report = generate_html_report(results)
        # with open("malware_report.html", "w") as f:
            # f.write(html_report)
        # print("Malware report saved as 'malware_report.html'.")
        #partitioning logic
        print("Found flagged hashes in the CSV file. Do you want to append a partition to the drive and move the malware? (y/n)")
        append_partition_choice = input().strip().lower()
        choices.append('y' if append_partition_choice == 'y' else 'n')

        # I broke this part too, gonna try to fix 
        if append_partition_choice == 'y':
            print("Available drives:")
            drives = get_drives()
            for drive in drives:
                print(drive)
            print("Enter the USB drive letter to append the partition (e.g., E, F):")
            drive_letter = input().strip().upper()
            choices.append(drive_letter)
            # Use the size of the largest flagged file for partition size
            max_size = max(get_file_size(f) for f in flagged_files)
            if append_partition(drive_letter, max_size + 512 * 1024 * 1024):
                # copy each flagged file to the new partition (next letter after the drive letter)
                new_drive_letter = chr(ord(drive_letter) + 1)
                for flagged_file in flagged_files:
                    name = os.path.basename(flagged_file)
                    new_file_path = f"{new_drive_letter}:/{name}"
                    try:
                        os.makedirs(f"{new_drive_letter}:/", exist_ok=True)
                        with open(flagged_file, 'rb') as src_file:
                            with open(new_file_path, 'wb') as dest_file:
                                dest_file.write(src_file.read())
                        print(f"File copied to {new_file_path}.")
                        # delete the original file
                        os.remove(flagged_file)
                        print(f"Original file {flagged_file} deleted.")
                    except Exception as e:
                        print(f"Error copying file {flagged_file}: {e}")
            
        else:
            print("Skipping partition appending.")
            choices.append('')

    else:
        print("No matching hashes found in CSV file. Skipping partition appending.")
        choices.append('n')
        choices.append('')
        
    
    # export the log file
    export_log(results, files, choices)


main()