import os
import hashlib
import subprocess
from datetime import datetime
from urllib.request import urlopen
from zipfile import ZipFile
from dotenv import load_dotenv
import wget
import pandas as pd
from flask import (
    Flask, render_template_string, request,
    send_file, redirect, url_for, flash
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key
CSV_LIST = "full.csv"

def active_cnx(timeout=5):
    try:
        urlopen("http://google.com", timeout=timeout)
        return True
    except:
        return False

def update_csv():
    if not active_cnx():
        return False, "No internet connection."
    url = "https://bazaar.abuse.ch/export/csv/full/"
    fname = wget.download(url)
    with ZipFile(fname, "r") as z:
        z.extractall()
    os.remove(fname)
    return True, f"Updated {CSV_LIST}"

def get_hash(path, func):
    h = func()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return '"' + h.hexdigest() + '"'

def compare_to_csv(path):
    # Check if CSV file exists first
    if not os.path.exists(CSV_LIST):
        return []  # Return empty list if CSV doesn't exist
    
    cols = ['first_seen_utc','sha256_hash','md5_hash','sha1_hash',
            'col4','col5','col6','col7','file_name','file_type_guess',
            'col10','col11','signature']
    try:
        df = pd.read_csv(CSV_LIST, on_bad_lines='skip', skiprows=range(9),
                         usecols=range(13), header=None, names=cols)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return []  # Return empty list if CSV can't be read
    flagged=[]
    for func,col in [(hashlib.md5,'md5_hash'),
                     (hashlib.sha1,'sha1_hash'),
                     (hashlib.sha256,'sha256_hash')]:
        hv=get_hash(path,func)
        matches=df[df[col]==hv]
        if not matches.empty:
            for _,r in matches.iterrows():
                flagged.append(r.to_dict())
    return flagged

def generate_html_report(rows):
    rows_html="\n".join(f"""
      <tr>
        <td>{r['first_seen_utc']}</td>
        <td>{r['sha256_hash']}</td>
        <td>{r['md5_hash']}</td>
        <td>{r['sha1_hash']}</td>
        <td>{r['file_name']}</td>
        <td>{r['file_type_guess']}</td>
        <td>{r['signature']}</td>
      </tr>""" for r in rows)
    return f"""
    <h2>Malware Scan Results</h2>
    <table border=1 cellpadding=5>
      <tr><th>First Seen</th><th>SHA256</th><th>MD5</th>
          <th>SHA1</th><th>File Name</th><th>Type Guess</th><th>Signature</th>
      </tr>
      {rows_html or '<tr><td colspan=7>No threats found.</td></tr>'}
    </table>"""

def export_log(rows, files, out_dir):
    log_name=f"Log_{datetime.now():%Y%m%d_%H%M%S}.txt"
    path=os.path.join(out_dir, log_name)
    with open(path, "w") as f:
        f.write("=== Scanned Files ===\n")
        for fp in files: f.write(fp+"\n")
        f.write("\n=== Flagged Hashes ===\n")
        if rows:
            for r in rows: f.write(str(r)+"\n")
        else:
            f.write("None\n")
    return log_name

def get_drives():
    drives = [f"{d}:" for d in "ABDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:")]
    return drives

def get_file_size(file_path):
    """Gets file size in bytes"""
    if os.path.isfile(file_path):
        return os.path.getsize(file_path)
    else:
        return None

def append_partition(drive_path, partition_size=100 * 1024 * 1024):  # Default 100MB
    # check if the drive exists
    if not drive_path.endswith(':'):
        drive_path += ':'
    if drive_path[0] not in ['C']:
        if not os.path.exists(drive_path):
            return False, f"Drive {drive_path} does not exist."
    elif drive_path[0] in ['C']:
        return False, f"Drive {drive_path} is a system drive and cannot be modified."
    
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
        if not disk_number.isdigit():
            return False, f"Could not determine disk number for drive {drive_path}."
    except Exception as e:
        return False, f"Error determining disk number: {e}"
    
    # create a new partition of the given size
    try:
        partition_cmd = (
            f"New-Partition -DiskNumber {disk_number} -Size {partition_size} "
            "-AssignDriveLetter | "
            "Format-Volume -FileSystem NTFS -NewFileSystemLabel 'USBDrive' -Confirm:$false"
        )
        subprocess.run(["powershell", "-Command", partition_cmd], check=True)
        return True, f"Partition of size {partition_size} bytes created on drive {drive_path}."
    except subprocess.CalledProcessError as e:
        return False, f"Error creating partition: {e}"

@app.route("/", methods=["GET"])
def index():
    # Check if CSV file exists and add warning if missing
    csv_warning = ""
    if not os.path.exists(CSV_LIST):
        csv_warning = """
        <div class="section" style="background-color:#fff3cd;border-color:#ffeaa7;">
          <h3 style="color:#856404;">⚠️ Warning</h3>
          <p style="color:#856404;">The malware hash database (full.csv) is missing. 
          Please click "Update Hash List" to download the latest malware signatures before scanning.</p>
        </div>
        """
    
    return render_template_string("""
    <!doctype html><html><head>
      <title>USBrakr Scanner</title>
      <style>form{margin-bottom:1em;}.side{display:flex;gap:1em;}
      .section{border:1px solid #ccc;padding:1em;margin:1em 0;}</style>
    </head><body>
      <h1>USBrakr Malware Scanner</h1>
      """ + csv_warning + """

      <div class="section">
        <h3>Scan Files</h3>
        <form method="post" action="{{ url_for('run_scan') }}" enctype="multipart/form-data">
          <p>Select files or folders to scan:</p>
          <input type="file" name="files" multiple webkitdirectory directory><br><br>
          
          <p><strong>OR</strong> enter local file/folder path:</p>
          <input type="text" name="local_path" placeholder="C:\\path\\to\\file\\or\\folder" style="width:300px;">
          <small style="display:block;color:#666;">For local files, original files can be quarantined</small><br>

          <p>Drive to save results:</p>
          <input type="text" name="save_drive" size="2" maxlength="1" required>
          <small>ex. E</small><br><br>

          <p>
            <input type="checkbox" name="append_partition" value="1">
            Create partition and quarantine flagged files
            <small style="display:block;color:#666;margin-top:4px;">
              Note: Uploaded files will be moved to quarantine partition if malware is detected
            </small>
          </p>

          <button type="submit">Run Scan & Save</button>
        </form>
      </div>

      <div class="section">
        <h3>Utilities</h3>
        <form method="post" action="{{ url_for('update_csv_route') }}" style="display:inline;">
          <button type="submit">Update Hash List</button>
        </form>

        <form method="post" action="{{ url_for('format_drive') }}" style="display:inline;margin-left:1em;">
          Drive: <input type="text" name="fmt_drive" size="2" maxlength="1" required>
          Size (GB): <input type="number" name="fmt_size" min="1" max="2048" value="10" style="width:60px;">
          <button type="submit">Format Drive</button>
        </form>

        <form method="post" action="{{ url_for('list_drives') }}" style="display:inline;margin-left:1em;">
          <button type="submit">List Available Drives</button>
        </form>
        
        <form method="post" action="{{ url_for('shutdown_app') }}" style="display:inline;margin-left:1em;">
          <button type="submit" style="background-color:#dc3545;color:white;" 
                  onclick="return confirm('Are you sure you want to shut down USBrakr Scanner?')">
            Shutdown Scanner
          </button>
        </form>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          <div class="section">
            <h3>Messages</h3>
            <ul>{% for cat,msg in messages %}
              <li><strong>{{cat.title()}}:</strong> {{msg}}</li>
            {% endfor %}</ul>
          </div>
        {% endif %}
      {% endwith %}
    </body></html>
    """)

@app.route("/run_scan", methods=["POST"])
def run_scan():
    files=request.files.getlist("files")
    local_path = request.form.get("local_path", "").strip()
    drive=request.form["save_drive"].strip().upper()
    create_partition = request.form.get("append_partition") == "1"
    
    if drive=="C":
        flash("Won't save to system C:", "error"); return redirect(url_for("index"))
    mount=f"{drive}:\\"
    if not os.path.exists(mount):
        flash(f"Drive {drive}: not found.", "error"); return redirect(url_for("index"))

    # Determine if we're working with uploaded files or local files
    is_local_scan = bool(local_path)
    paths = []
    
    if is_local_scan:
        # Handle local file/folder scanning
        if not os.path.exists(local_path):
            flash(f"Local path {local_path} does not exist.", "error")
            return redirect(url_for("index"))
        
        if os.path.isfile(local_path):
            paths = [local_path]
        elif os.path.isdir(local_path):
            paths = [os.path.join(local_path, f) for f in os.listdir(local_path) 
                    if os.path.isfile(os.path.join(local_path, f))]
        else:
            flash("Invalid local path.", "error")
            return redirect(url_for("index"))
    else:
        # Handle uploaded files
        if not files or not any(f.filename for f in files):
            flash("No files uploaded or local path provided.", "error")
            return redirect(url_for("index"))
            
        tmp="temp"; os.makedirs(tmp,exist_ok=True)
        for f in files:
            if f.filename:  # Check if file has a name
                p=os.path.join(tmp,f.filename)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                f.save(p)
                paths.append(p)

    # Check if CSV file exists before scanning
    if not os.path.exists(CSV_LIST):
        flash("Malware hash database (full.csv) is missing. Please update the hash list first.", "error")
        return redirect(url_for("index"))

    # scan
    flagged=[]
    flagged_files=[]
    try:
        for p in paths: 
            result = compare_to_csv(p)
            if result:
                flagged.extend(result)
                flagged_files.append(p)
    except Exception as e:
        flash(f"Error during scanning: {str(e)}", "error")
        return redirect(url_for("index"))

    # Handle partition creation for flagged files
    partition_msg = ""
    if flagged_files and create_partition:
        # Calculate partition size based on largest flagged file + buffer
        max_size = max(get_file_size(f) for f in flagged_files if get_file_size(f))
        partition_size = max_size + 100 * 1024 * 1024  # Add 100MB buffer
        
        success, msg = append_partition(drive, partition_size)
        if success:
            import shutil
            new_drive_letter = chr(ord(drive) + 1)
            new_mount = f"{new_drive_letter}:\\"
            
            if os.path.exists(new_mount):
                moved_files = []
                for flagged_file in flagged_files:
                    name = os.path.basename(flagged_file)
                    new_path = os.path.join(new_mount, name)
                    try:
                        # Move flagged files to quarantine
                        shutil.move(flagged_file, new_path)
                        moved_files.append(name)
                    except Exception as e:
                        flash(f"Error moving {name}: {e}", "error")
                
                action = "quarantined from original location" if is_local_scan else "quarantined from upload"
                partition_msg = f"Created partition on {new_drive_letter}: and {action} {len(moved_files)} flagged files."
            else:
                partition_msg = "Partition created but new drive not accessible."
        else:
            partition_msg = f"Partition creation failed: {msg}"

    # report & log locally then copy to drive
    report=generate_html_report(flagged)
    html_name="report.html"
    with open(html_name,"w") as h: h.write(report)
    log_name=export_log(flagged, paths, ".")

    # Use shutil.move() instead of os.replace() for cross-drive moves
    import shutil
    shutil.move(html_name, os.path.join(mount, html_name))
    shutil.move(log_name,  os.path.join(mount, log_name))

    # cleanup temp only if we used uploaded files
    if not is_local_scan and 'tmp' in locals():
        shutil.rmtree(tmp)

    return render_template_string("""
      <h1>Scan Complete</h1>
      {{ report|safe }}
      <p>Report & log saved to drive {{drive}}:</p>
      {% if partition_msg %}
        <p><strong>Partition Status:</strong> {{partition_msg}}</p>
      {% endif %}
      <p><a href="{{ url_for('index') }}">&#x2190; Back</a></p>
    """, report=report, drive=drive, partition_msg=partition_msg)

@app.route("/update_csv", methods=["POST"])
def update_csv_route():
    ok,msg=update_csv()
    flash(msg, "success" if ok else "error")
    return redirect(url_for("index"))

@app.route("/list_drives", methods=["POST"])
def list_drives():
    drives = get_drives()
    if drives:
        flash(f"Available drives: {', '.join(drives)}", "success")
    else:
        flash("No drives found", "error")
    return redirect(url_for("index"))

@app.route("/format_drive", methods=["POST"])
def format_drive():
    d=request.form["fmt_drive"].strip().upper()
    size_gb = request.form.get("fmt_size", "10").strip()
    
    if d=="C":
        flash("Refusing C:", "error")
        return redirect(url_for("index"))
    
    try:
        size_gb = int(size_gb)
        if size_gb < 1 or size_gb > 2048:
            flash("Size must be between 1 GB and 2048 GB", "error")
            return redirect(url_for("index"))
    except ValueError:
        flash("Invalid size specified", "error")
        return redirect(url_for("index"))
    
    # Calculate size in MB for the format command
    size_mb = size_gb * 1024
    
    # Use PowerShell for more reliable formatting with custom size
    ps_cmd = f"""
    try {{
        $disk = Get-Disk | Where-Object {{ (Get-Partition -DiskNumber $_.Number | Where-Object {{ $_.DriveLetter -eq '{d}' }}) }}
        if ($disk) {{
            Clear-Disk -Number $disk.Number -RemoveData -Confirm:$false
            New-Partition -DiskNumber $disk.Number -Size {size_mb}MB -DriveLetter {d} | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'USBDrive' -Confirm:$false
            Write-Output "SUCCESS"
        }} else {{
            Write-Output "DRIVE_NOT_FOUND"
        }}
    }} catch {{
        Write-Output "ERROR: $($_.Exception.Message)"
    }}
    """
    
    try:
        result = subprocess.check_output(
            ["powershell", "-Command", ps_cmd],
            universal_newlines=True,
            stderr=subprocess.STDOUT
        ).strip()
        
        if "SUCCESS" in result:
            flash(f"Formatted {d}: ({size_gb} GB) successfully", "success")
        elif "DRIVE_NOT_FOUND" in result:
            flash(f"Drive {d}: not found or not accessible", "error")
        else:
            flash(f"Format {d}: failed - {result}", "error")
    except subprocess.CalledProcessError as e:
        flash(f"Format {d}: failed - {e.output}", "error")
    except Exception as e:
        flash(f"Format {d}: failed - {str(e)}", "error")
    
    return redirect(url_for("index"))

@app.route("/shutdown", methods=["POST"])
def shutdown_app():
    def shutdown_server():
        time.sleep(1)  # Give time for the response to be sent
        import os
        os._exit(0)  # Force exit the application
    
    import threading
    import time
    threading.Thread(target=shutdown_server, daemon=True).start()
    
    return render_template_string("""
    <!doctype html><html><head>
      <title>USBrakr Scanner - Shutting Down</title>
      <style>body{font-family:Arial,sans-serif;text-align:center;margin-top:100px;}</style>
    </head><body>
      <h1>USBrakr Scanner Shutting Down...</h1>
      <p>The application will close in a few seconds.</p>
      <p>Thank you for using USBrakr Scanner!</p>
      <script>
        setTimeout(function() {
          window.close();
        }, 2000);
      </script>
    </body></html>
    """)

if __name__=="__main__":
    import threading
    import webbrowser
    import time
    import subprocess
    
    def open_browser():
        time.sleep(1.5)  # Wait for Flask to start
        webbrowser.open('http://127.0.0.1:5000')
    
    # Start browser and terminal in separate threads
    threading.Thread(target=open_browser, daemon=True).start()
    
    print("USBrakr Scanner starting...")
    print("Web interface will open automatically.")
    print("Terminal window will also open for system operations.")
    print("If browser doesn't open, go to: http://127.0.0.1:5000")
    print("Press Ctrl+C to stop the scanner")
    
    app.run(debug=False, host='127.0.0.1', port=5000)
