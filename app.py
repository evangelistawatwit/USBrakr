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
if "FLASK_SECRET_KEY" not in os.environ:
    raise RuntimeError("FLASK_SECRET_KEY not set")

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
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
    return h.hexdigest()

def compare_to_csv(path):
    cols = ['first_seen_utc','sha256_hash','md5_hash','sha1_hash',
            'col4','col5','col6','col7','file_name','file_type_guess',
            'col10','col11','signature']
    df = pd.read_csv(CSV_LIST, on_bad_lines='skip', skiprows=range(9),
                     usecols=range(13), header=None, names=cols)
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

@app.route("/", methods=["GET"])
def index():
    return render_template_string("""
    <!doctype html><html><head>
      <title>USBrakr Scanner</title>
      <style>form{margin-bottom:1em;}.side{display:flex;gap:1em;}</style>
    </head><body>
      <h1>USBrakr Malware Scanner</h1>

      <form method="post" action="{{ url_for('run_scan') }}" enctype="multipart/form-data">
        <h3>Select files or folders to scan:</h3>
        <input type="file" name="files" multiple webkitdirectory directory required><br><br>

        <h3>Drive to save results:</h3>
        <input type="text" name="save_drive" size="2" maxlength="1" required>
        <small>ex. E</small><br><br>

        <button type="submit">Run Scan & Save</button>
      </form>

      <form method="post" action="{{ url_for('update_csv') }}">
        <button type="submit">Update Hash List</button>
      </form>

      <form method="post" action="{{ url_for('format_drive') }}">
        <h3>Format Drive</h3>
        Drive: <input type="text" name="fmt_drive" size="2" maxlength="1" required><br><br>
        <button type="submit">Format Drive</button>
      </form>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          <ul>{% for cat,msg in messages %}
            <li><strong>{{cat.title()}}:</strong> {{msg}}</li>
          {% endfor %}</ul>
        {% endif %}
      {% endwith %}
    </body></html>
    """)

@app.route("/run_scan", methods=["POST"])
def run_scan():
    files=request.files.getlist("files")
    drive=request.form["save_drive"].strip().upper()
    if drive=="C":
        flash("Won’t save to system C:", "error"); return redirect(url_for("index"))
    mount=f"{drive}:\\"
    if not os.path.exists(mount):
        flash(f"Drive {drive}: not found.", "error"); return redirect(url_for("index"))

    # save uploads temporarily
    tmp="temp"; os.makedirs(tmp,exist_ok=True)
    paths=[]
    for f in files:
        p=os.path.join(tmp,f.filename); f.save(p); paths.append(p)

    # scan
    flagged=[]
    for p in paths: flagged.extend(compare_to_csv(p))

    # report & log locally then copy to drive
    report=generate_html_report(flagged)
    html_name="report.html"
    with open(html_name,"w") as h: h.write(report)
    log_name=export_log(flagged, paths, ".")

    os.replace(html_name, os.path.join(mount, html_name))
    os.replace(log_name,  os.path.join(mount, log_name))

    # cleanup temp
    for p in paths: os.remove(p)

    return render_template_string("""
      <h1>Scan Complete</h1>
      {{ report|safe }}
      <p>Report & log saved to drive {{drive}}:</p>
      <p><a href="{{ url_for('index') }}">&#x2190; Back</a></p>
    """, report=report, drive=drive)

@app.route("/update_csv", methods=["POST"])
def update_csv():
    ok,msg=update_csv()
    flash(msg, "success" if ok else "error")
    return redirect(url_for("index"))

@app.route("/format_drive", methods=["POST"])
def format_drive():
    d=request.form["fmt_drive"].strip().upper()
    if d=="C":
        flash("Refusing C:", "error")
    else:
        ok=os.system(f'format {d}: /FS:NTFS /Q /X /Y')==0
        flash(f"Formatted {d}:" if ok else f"Format {d}: failed", "success" if ok else "error")
    return redirect(url_for("index"))

if __name__=="__main__":
    app.run(debug=True)
