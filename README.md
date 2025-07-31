# USBrakr
A plug-and-play scanner for malware detection and isolation from a USB drive.
## Description
This project is designed for computer systems taken offline due to suspicious file downloads or execution. It allows the user to scan a file or directory for known malware. Any flagged files will be quarantined in a specified external drive. An HTML threat report is saved locally and displayed to the user. This program has a console-driven version with dialogue boxes, and an application version compiled into an .exe file. Both versions are executable directly from an external USB drive.

## Getting Started
The following steps are to create the executable file, or run the console version.
### Installing Python
This script requires Python 3 to run via console.
* Windows:
```
winget install python3
```
* Linux: 
```
sudo apt update
sudo apt install python3 python3-pip
```
* macOS: https://www.python.org/downloads/macos/
    * Verify the installation of Python 3.
```
python3 --version
```
### Dependencies
Install the following dependencies.
```
python3 -m pip install -r requirements.txt
```
### Compiling into Executable
```
pyinstaller --onefile --windowed --uac-admin --name "USBrakr_Scanner" app.py
```
### Executing the program
Console with dialogue boxes
```
python main.py
```
App version of scanner
```
python app.py
```
* If using compiled .EXE, ensure the full.csv hashlist is in the same directory as the .EXE or .PY file.

## Authors
Conner Pattison - [@patt-co](https://github.com/patt-co)

William Evangelista - [@evangelistawatwit](https://github.com/evangelistawatwit)
### Version History
* v0.1
    * Local virus scanner
* v0.2
    * Reads/writes to external drives
* v0.3
    * Updates from internet
* v0.4
    * Saves matching hashes
    * Generates html threat report file
* v0.5
    * Generates txt log file
    * Created directory scanner
* v0.6
    * Adds dialogue boxes
    * Completed console version
* v0.9
    * Flask page for app version
* v1.0
    * Compiles to executable version
    
## Acknowledgements
* Malware detection by hash
    * [eng-MohamedFayed](https://github.com/eng-MohamedFayed/): [malware-detection-by-hash](https://github.com/eng-MohamedFayed/malware-detection-by-hash)
* HTML formatting in Python
    * [Rubarion](https://github.com/Rubarion/): [py4html](https://github.com/Rubarion/py4html)
* Malware samples for testing
    * [Cybersight-Security](https://github.com/Cybersight-Security/): [Malware-Samples](https://github.com/Cybersight-Security/Malware-Samples)
