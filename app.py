import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import yaml
import pandas as pd
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import paramiko
from modules.connectivity import check_ssh_connectivity, sftp_upload_files_with_pem
import json


import time
PRECHECK_DIR = "/home/KnfUser/PrecheckLogs"
if not os.path.isdir(PRECHECK_DIR):
    try:
        os.makedirs(PRECHECK_DIR, exist_ok=True)
    except Exception as e:
        print("Could not create PRECHECK_DIR:", e)

# Absolute path for Packages folder
PACKAGES_DIR = "/home/KnfUser/Packages/2025-11-11"

# --- Load config ---
with open("config.yaml", "r") as f:
    cfg = yaml.safe_load(f)

AUTH = cfg.get("auth", {})
ALLOWED_EXT = set(cfg.get("upload", {}).get("allowed_extensions", ["xls", "xlsx"]))

# --- Flask App setup ---
app = Flask(__name__)
app.secret_key = cfg.get("flask", {}).get("secret_key", "dev_secret_key")

# --- SQLite Database setup ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


@app.route("/packages")
def packages():
    all_packages = Packages.query.all()
    return render_template("packages.html", packages=all_packages, username=session.get("username"))



# =======================
# Models
# =======================
class Upload(db.Model):
    __tablename__ = "uploads"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    rows = db.Column(db.Integer, default=0)
    cols = db.Column(db.Integer, default=0)
    note = db.Column(db.String(512))
    hosts = db.relationship("HostEntry", back_populates="upload", cascade="all, delete-orphan")

class HostEntry(db.Model):
    __tablename__ = "hosts"
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey("uploads.id"), nullable=False)
    host = db.Column(db.String(256), nullable=False)
    ssh_user = db.Column(db.String(128), nullable=True)
    pem_path = db.Column(db.String(512), nullable=True)
    # NEW FIELDS
    location = db.Column(db.String(128), nullable=True)
    email = db.Column(db.String(128), nullable=True)
    status = db.Column(db.String(32), default="pending")  # pending / connected / failed / patched
    message = db.Column(db.String(1024), nullable=True)
    last_checked = db.Column(db.DateTime, nullable=True)
    last_patched = db.Column(db.DateTime, nullable=True)
    upload = db.relationship("Upload", back_populates="hosts")


class Packages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patch = db.Column(db.String(200))
    patch_id = db.Column(db.String(50))
    category = db.Column(db.String(100))
    downloaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class PatchLog(db.Model):
    __tablename__ = "patch_logs"
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, nullable=True)
    host_id = db.Column(db.Integer, nullable=True)
    host = db.Column(db.String(256))
    action = db.Column(db.String(128))
    status = db.Column(db.String(32))
    message = db.Column(db.String(2048))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.Column(db.String(32))  

# =======================
# Helpers
# =======================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def find_column(columns, possible_names):
    """
    Return the *index* of the first column whose name matches one of possible_names
    (case-insensitive, substring match). If not found, return None.
    """
    cols_norm = [str(c).strip().lower() for c in columns]

    for name in possible_names:
        name = name.lower()
        for i, col in enumerate(cols_norm):
            if name == col or name in col:
                return i
    return None



def run_patch_on_host(host, username, pem_path, command="echo patched", timeout=30):
    """Run a simple patch command on host via SSH and return status/msg. Keep command minimal here."""
    try:
        if not pem_path or not os.path.exists(pem_path):
            return {"host": host, "ok": False, "msg": f"PEM not found: {pem_path}"}
        key = None
        try:
            key = paramiko.RSAKey.from_private_key_file(pem_path)
        except Exception:
            try:
                key = paramiko.Ed25519Key.from_private_key_file(pem_path)
            except Exception:
                key = None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = dict(hostname=str(host).strip(), username=username, timeout=10)
        if key:
            connect_kwargs["pkey"] = key
        else:
            connect_kwargs["key_filename"] = pem_path

        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        client.close()
        if err:
            return {"host": host, "ok": False, "msg": f"stderr: {err}"}
        return {"host": host, "ok": True, "msg": out or "patched"}
    except Exception as e:
        return {"host": host, "ok": False, "msg": str(e)}

# =======================
# Routes
# =======================
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))


#login multiple users logic#
from pathlib import Path

cfg_path = Path("config.yaml")
if cfg_path.exists():
    with cfg_path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
else:
    cfg = {}

# Build a username->password dict
USERS = {u["username"]: u["password"] for u in cfg.get("auth", {}).get("users", [])}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Look up expected password for this username
        expected = USERS.get(username)
        if expected and password == expected:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -----------------------
# Dashboard (upload & preview)
# -----------------------
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    preview_html = None
    filename = None
    rows = cols = 0

    # -----------------------
    # POST: handle Excel upload
    # -----------------------
    if request.method == "POST":
        file = request.files.get("file")

        # Basic validations
        if not file or file.filename == "":
            flash("No file selected.", "warning")
            return redirect(url_for("dashboard"))

        if not allowed_file(file.filename):
            flash("Invalid file type. Only .xls/.xlsx allowed.", "warning")
            return redirect(url_for("dashboard"))

        filename = file.filename

        # Read Excel
        df = pd.read_excel(BytesIO(file.read()))
        rows, cols = df.shape

        # Use original columns for mapping
        columns = list(df.columns)

        # Detect columns (case-insensitive, substring match)
        host_col     = find_column(columns, ["host", "hostname", "ip address", "ip"])
        ssh_col      = find_column(columns, ["ssh_user", "username", "user"])
        pem_col      = find_column(columns, ["pem path", "pem_file", "pem", "key", "keyfile"])
        location_col = find_column(columns, ["location", "site", "city"])
        email_col    = find_column(columns, ["email", "mail"])

        # Host column is mandatory
        if host_col is None:
            flash("No host column found in the Excel.", "warning")
            return redirect(url_for("dashboard"))

        # Create upload entry
        upload = Upload(filename=filename, rows=rows, cols=cols)
        db.session.add(upload)
        db.session.flush()   # so upload.id is available

        # Insert / update hosts
        for _, r in df.iterrows():
            host_val = str(r.iloc[host_col]).strip()
            if not host_val:
                continue

            ssh_user  = str(r.iloc[ssh_col]).strip() if ssh_col is not None else None
            pem_path  = str(r.iloc[pem_col]).strip() if pem_col is not None else None
            location  = str(r.iloc[location_col]).strip() if location_col is not None else None
            email     = str(r.iloc[email_col]).strip() if email_col is not None else None

            existing = HostEntry.query.filter_by(host=host_val).first()

            if existing:
                existing.upload_id = upload.id
                if ssh_user:
                    existing.ssh_user = ssh_user
                if pem_path:
                    existing.pem_path = pem_path
                if location:
                    existing.location = location
                if email:
                    existing.email = email
            else:
                db.session.add(
                    HostEntry(
                        upload_id=upload.id,
                        host=host_val,
                        ssh_user=ssh_user or None,
                        pem_path=pem_path or None,
                        location=location or None,
                        email=email or None,
                    )
                )

        db.session.commit()
        session["current_upload_id"] = upload.id
        flash("Servers are successfully onboarded. Navigate to Patch Management for further actions.", "success")
        return redirect(url_for("dashboard"))

    # -----------------------
    # GET: show current upload preview
    # -----------------------
    current_upload_id = session.get("current_upload_id")

    if current_upload_id:
        upload = Upload.query.get(current_upload_id)
        if upload:
            hosts = HostEntry.query.filter_by(upload_id=current_upload_id).limit(50).all()

            if hosts:
                df_preview = pd.DataFrame([
                    {
                        "Host": h.host,
                        "SSH User": h.ssh_user or "",
                        "PEM": h.pem_path or "",
                        "Location": h.location or "",
                        "Email": h.email or "",
                        "Status": h.status or "pending",
                    }
                    for h in hosts
                ])
                preview_html = df_preview.to_html(
                    classes="table table-striped table-sm",
                    index=False,
                    escape=False,
                )

            filename = upload.filename
            rows, cols = upload.rows, upload.cols

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        preview_table=preview_html,
        filename=filename,
        rows=rows,
        cols=cols,
        current_upload_id=current_upload_id,
    )


# -----------------------
# Inventory - show ALL hosts across uploads
# -----------------------
@app.route("/inventory", methods=["GET"])
@login_required
def inventory():
    # Render an inventory page; templates/inventory.html should list hosts or call the API below
    return render_template("inventory.html", username=session.get("username"))

@app.route("/api/inventory", methods=["GET"])
@login_required
def api_inventory():
    # Return JSON of all hosts across uploads (id, host, upload_id, upload_time, status, last_checked)
    rows = []
    for h in HostEntry.query.order_by(HostEntry.upload_id.desc()).all():
        rows.append({
            "id": h.id,
            "host": h.host,
            "ssh_user": h.ssh_user,
            "pem_path": h.pem_path,
            "location": h.location,        
            "email": h.email,              
            "status": h.status,
            "last_checked": h.last_checked.isoformat() if h.last_checked else None,
            "upload_id": h.upload_id
        })
    return jsonify(rows)

# -----------------------
# Patch Management - operates ONLY on current upload
# -----------------------
@app.route("/patch_management", methods=["GET"])
@login_required
def patch_management():
    current_upload_id = session.get("current_upload_id")
    upload = None
    hosts = []

    if current_upload_id:
        upload = Upload.query.get(current_upload_id)
        if upload:
            hosts = HostEntry.query.filter_by(upload_id=current_upload_id).all()

    # Even if there's no upload, we render page with empty data
    if not upload:
        flash("No current upload found. Please upload a file from the dashboard.", "warning")

    return render_template(
        "patch_management.html",
        username=session.get("username"),
        upload=upload,
        hosts=hosts
    )


@app.route("/patch_management_all", methods=["GET"])
@login_required
def patch_management_all():
    # show ALL hosts across all uploads (not just current upload)
    hosts = HostEntry.query.all()

    return render_template(
        "patch_management.html",
        username=session.get("username"),
        upload=None,
        hosts=hosts
    )



@app.route("/patch_check", methods=["POST"])
@login_required
def patch_check():
    """
    POST expects: host_ids[]  (list of host entry ids)
    Runs connectivity checks on those hosts and updates host.status and message.
    Returns JSON results per-host.
    """
    host_ids = request.form.getlist("host_ids[]")
    if not host_ids:
        return jsonify({"error": "host_ids[] required"}), 400

    results = []
    for hid in host_ids:
        he = HostEntry.query.get(int(hid))
        if not he:
            results.append({"id": hid, "ok": False, "msg": "Host not found"})
            continue
        if not he.ssh_user or not he.pem_path:
            he.status = "failed"
            he.message = "Missing ssh_user or pem_path"
            he.last_checked = datetime.utcnow()
            db.session.add(he)
            db.session.commit()

            # Add connectivity log entry for missing ssh/pem
            try:
                username = session.get("username", "unknown")
                log = PatchLog(
                    upload_id=he.upload_id if getattr(he, "upload_id", None) else None,
                    host_id=he.id,
                    host=he.host,
                    action="Connectivity Check",
                    status="failed",
                    message=he.message,
                    user=username
                )
                db.session.add(log)
                db.session.commit()
            except Exception as e:
                print("Failed to add PatchLog for connectivity (missing details):", e)

            results.append({"id": he.id, "host": he.host, "ok": False, "msg": he.message})  
            continue

        res = check_ssh_connectivity(he.host, he.ssh_user, he.pem_path)
        he.status = "connected" if res["ok"] else "failed"
        he.message = res["msg"]
        he.last_checked = datetime.utcnow()
        db.session.add(he)
        db.session.commit()

        # ----- NEW: write a PatchLog entry for this connectivity check -----
        try:
            username = session.get("username", "unknown")
            log = PatchLog(
                upload_id=he.upload_id if getattr(he, "upload_id", None) else None,
                host_id=he.id,
                host=he.host,
                action="Connectivity Check",
                status="success" if res["ok"] else "failed",
                message=res["msg"],
                user=username
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            print("Failed to add PatchLog for connectivity:", e)
        # ------------------------------------------------------------------

        results.append({"id": he.id, "host": he.host, "ok": res["ok"], "msg": res["msg"]})
    return jsonify({"results": results})





# ---------- Run sequence pre/post checks (improved) ----------
@app.route("/run_checks", methods=["POST"])
@login_required
def run_checks():
    """
    Run the sequence of pre/post checks on selected hosts.
    POST params:
      - host_ids[]  (list of HostEntry ids)
      - kind        ("pre" or "post")
    Saves JSON: PRECHECK_DIR/<host>_<kind>_<ts>.json
    For post, compares with latest pre JSON and returns a minimal diff.
    """
    host_ids = request.form.getlist("host_ids[]")
    kind = request.form.get("kind", "pre").lower()
    if kind not in ("pre", "post"):
        return jsonify({"error": "kind must be 'pre' or 'post'"}), 400
    if not host_ids:
        return jsonify({"error": "host_ids[] required"}), 400

    results = []
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    cmds = [
        "uptime",
        "uname -a",
        "cat /etc/*-release || true",
        "df -h",
        "ifconfig || ip addr",
        "netstat -in || true",
        "netstat -rn || ip route || true",
        "cat /etc/fstab || true"
    ]
    sep = "___CHKSEP___"
    full_cmd = f"set -e; " + ("; echo '%s'; " % sep).join(cmds) + f"; echo '{sep}'"

    username = session.get("username", "unknown")

    for hid in host_ids:
        he = HostEntry.query.get(int(hid))
        if not he:
            results.append({"id": hid, "ok": False, "msg": "Host not found"})
            continue

        # enforce sequence: pre allowed only if connected; post only if patched
        if kind == "pre" and he.status != "connected":
            msg = "Pre-check allowed only for connected hosts"
            # immediate PatchLog entry for attempted pre-check
            try:
                log = PatchLog(
                    upload_id=getattr(he, "upload_id", None),
                    host_id=he.id,
                    host=he.host,
                    action="Pre-check",
                    status="failed",
                    message=msg,
                    user=username
                )
                db.session.add(log); db.session.commit()
            except Exception as e:
                print("Failed to add PatchLog (pre-check enforce):", e)
            results.append({"id": he.id, "host": he.host, "ok": False, "msg": msg})
            continue
        if kind == "post" and he.status not in ("patched", "success"):

            msg = "Post-check allowed only for patched hosts"
            try:
                log = PatchLog(
                    upload_id=getattr(he, "upload_id", None),
                    host_id=he.id,
                    host=he.host,
                    action="Post-check",
                    status="failed",
                    message=msg,
                    user=username
                )
                db.session.add(log); db.session.commit()
            except Exception as e:
                print("Failed to add PatchLog (post-check enforce):", e)
            results.append({"id": he.id, "host": he.host, "ok": False, "msg": msg})
            continue

        out_text = ""
        ok = True
        msg = ""
        try:
            # load key if possible (Ed25519 / RSA)
            key = None
            try:
                key = paramiko.RSAKey.from_private_key_file(he.pem_path)
            except Exception:
                try:
                    key = paramiko.Ed25519Key.from_private_key_file(he.pem_path)
                except Exception:
                    key = None

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = dict(hostname=str(he.host).strip(), username=he.ssh_user, timeout=60)
            if key:
                kwargs["pkey"] = key
            else:
                kwargs["key_filename"] = he.pem_path

            client.connect(**kwargs)
            stdin, stdout, stderr = client.exec_command(full_cmd, timeout=300)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            client.close()
            out_text = out + ("\n\nSTDERR:\n" + err if err else "")
        except Exception as e:
            ok = False
            msg = f"SSH/command failed: {e}"
            out_text = msg

        # parse outputs
        parts = [p.strip() for p in out_text.split(sep) if p.strip()]
        parsed = {}
        parsed["uptime_raw"] = parts[0] if len(parts) > 0 else ""
        parsed["uname_raw"] = parts[1] if len(parts) > 1 else ""
        parsed["release_raw"] = parts[2] if len(parts) > 2 else ""
        parsed["df_raw"] = parts[3] if len(parts) > 3 else ""
        parsed["ifconfig_raw"] = parts[4] if len(parts) > 4 else ""
        parsed["netstat_in_raw"] = parts[5] if len(parts) > 5 else ""
        parsed["netstat_rn_raw"] = parts[6] if len(parts) > 6 else ""
        parsed["fstab_raw"] = parts[7] if len(parts) > 7 else ""

        # light parsing
        try:
            up = parsed.get("uptime_raw", "")
            if "load average" in up:
                load_part = up.split("load average:")[-1].strip()
                parsed["load"] = [float(x.strip().strip(',')) for x in load_part.replace(',', ' ').split()[:3] if x.replace('.', '', 1).replace(',', '', 1).isdigit()][:3]
            ua = parsed.get("uname_raw","").split()
            parsed["kernel"] = ua[2] if len(ua) > 2 else parsed.get("uname_raw","")
            parsed["hostname"] = ua[1] if len(ua) > 1 else he.host
            dfraw = parsed.get("df_raw","").splitlines()
            parsed["disks"] = []
            for row in dfraw[1:]:
                cols = [c for c in row.split() if c]
                if len(cols) >= 6:
                    filesystem, size, used, avail, usep, mount = cols[0], cols[1], cols[2], cols[3], cols[4], cols[5]
                    parsed["disks"].append({"filesystem": filesystem, "size": size, "used": used, "avail": avail, "use_percent": usep, "mount": mount})
            ifcfg = parsed.get("ifconfig_raw","")
            primary_ip = None
            for line in ifcfg.splitlines():
                if "inet " in line and "127.0.0.1" not in line:
                    toks = line.strip().split()
                    try:
                        iidx = toks.index("inet")
                        primary_ip = toks[iidx+1]
                        break
                    except Exception:
                        continue
            parsed["primary_ip"] = primary_ip
            rns = parsed.get("netstat_rn_raw","").splitlines()
            default_gw = None
            for r in rns:
                if r.strip().startswith("0.0.0.0") or r.strip().startswith("default"):
                    cols = [c for c in r.split() if c]
                    if len(cols) >= 2:
                        default_gw = cols[1]
                        break
            parsed["default_gateway"] = default_gw
            parsed["fstab_lines"] = [l for l in parsed.get("fstab_raw","").splitlines() if l.strip() and not l.strip().startswith("#")]
        except Exception:
            pass

        # Save JSON
        fname = f"{he.host}_{kind}_{ts}.json"
        fpath = os.path.join(PRECHECK_DIR, fname)
        to_save = {
            "host": he.host,
            "id": he.id,
            "kind": kind,
            "ts": ts,
            "ok": ok,
            "msg": msg,
            "parsed": parsed,
            "raw": parsed.get("uptime_raw","") + "\n\n" + parsed.get("df_raw","")
        }
        try:
            os.makedirs(PRECHECK_DIR, exist_ok=True)
            with open(fpath, "w") as fh:
                json.dump(to_save, fh, indent=2)
        except Exception as e:
            print("Failed to write precheck file:", e)

        # update host status/message
        if kind == "pre":
            he.status = "precheck_passed" if ok else "precheck_failed"
        else:
            he.status = "postcheck_passed" if ok else "postcheck_failed"
        # message contains summary + path so Log History shows useful info
        short_summary = []
        if parsed.get("kernel"): short_summary.append(f"kernel={parsed.get('kernel')}")
        if parsed.get("primary_ip"): short_summary.append(f"ip={parsed.get('primary_ip')}")
        # root use percent (if found)
        root_use = ""
        for d in parsed.get("disks", []):
            if d.get("mount") == "/":
                root_use = d.get("use_percent","")
                break
        if root_use: short_summary.append(f"root_use={root_use}")
        he.message = f"{'OK' if ok else 'FAILED'}: {', '.join(short_summary)} -- {fpath}"
        he.last_checked = datetime.utcnow()
        db.session.add(he)
        db.session.commit()

        # write PatchLog entry (with filepath + small summary)
        try:
            action_name = "Pre-check" if kind == "pre" else "Post-check"
            log_msg = f"{fpath} | {', '.join(short_summary) if short_summary else ''}"
            log = PatchLog(
                upload_id=getattr(he, "upload_id", None),
                host_id=he.id,
                host=he.host,
                action=action_name,
                status="success" if ok else "failed",
                message=log_msg,
                user=username
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            print("Failed to add PatchLog for checks:", e)

        # If post-check, compare with latest pre JSON and compute minimal diff
        diff = {}
        if kind == "post":
            try:
                pre_files = [p for p in os.listdir(PRECHECK_DIR) if p.startswith(f"{he.host}_pre_")]
                pre_files_sorted = sorted(pre_files, reverse=True)
                if pre_files_sorted:
                    pre_path = os.path.join(PRECHECK_DIR, pre_files_sorted[0])
                    with open(pre_path, "r") as fh:
                        pre_json = json.load(fh)
                    pre_parsed = pre_json.get("parsed", {})
                    post_parsed = to_save.get("parsed", {})
                    changed = []
                    def root_use_val(parsed):
                        for d in parsed.get("disks", []):
                            if d.get("mount") == "/":
                                return d.get("use_percent","")
                        return ""
                    pre_root = root_use_val(pre_parsed)
                    post_root = root_use_val(post_parsed)
                    if pre_root != post_root:
                        changed.append({"field":"root_use", "before": pre_root, "after": post_root})
                    if pre_parsed.get("kernel") != post_parsed.get("kernel"):
                        changed.append({"field":"kernel", "before": pre_parsed.get("kernel"), "after": post_parsed.get("kernel")})
                    if pre_parsed.get("default_gateway") != post_parsed.get("default_gateway"):
                        changed.append({"field":"default_gateway", "before": pre_parsed.get("default_gateway"), "after": post_parsed.get("default_gateway")})
                    if pre_parsed.get("fstab_lines") != post_parsed.get("fstab_lines"):
                        changed.append({"field":"fstab", "before": len(pre_parsed.get("fstab_lines",[])), "after": len(post_parsed.get("fstab_lines",[]))})
                    diff = {"pre_file": pre_path, "changes": changed, "ok": len(changed) == 0}
                else:
                    diff = {"warning": "no precheck file found to compare"}
            except Exception as e:
                diff = {"error": f"failed to read/compare pre file: {e}"}

        item = {"id": he.id, "host": he.host, "ok": ok, "msg": msg or ("OK" if ok else "FAILED"), "json_file": fpath}
        if kind == "post":
            item["diff"] = diff
        results.append(item)

    return jsonify({"results": results, "ts": ts})



import threading
import traceback

def do_patch_job(host_ids, current_upload_id, packages_path, deb_files, username, ts):
    """
    Background worker: performs SFTP + SSH install for each host and updates DB.
    Must be called under app.app_context() or wrap with app.app_context() here.
    """
    with app.app_context():
        summary = {"ts": ts, "packages_path": packages_path, "hosts": []}
        for hid in host_ids:
            try:
                he = HostEntry.query.get(int(hid))
                if not he:
                    print(f"[BG] Host id {hid} not found, skipping.")
                    continue

                host_summary = {"id": he.id, "host": he.host}
                print(f"[BG] Uploading to {he.host} -> /tmp/controller_patches/packages_{ts}_{he.id}")

                remote_dir = os.path.join("/tmp/controller_patches", f"packages_{ts}_{he.id}")

                # SFTP upload
                ok_up, up_details = sftp_upload_files_with_pem(
                    he.host, he.ssh_user, he.pem_path, deb_files, remote_dir
                )
                print(f"[BG] SFTP result for {he.host}: {up_details}")
                host_summary["uploaded"] = up_details.get("uploaded", [])
                if not ok_up:
                    raise Exception(up_details.get("error") or "SFTP upload failed")

                # SSH and install
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                key = None
                try:
                    key = paramiko.RSAKey.from_private_key_file(he.pem_path)
                except Exception:
                    try:
                        key = paramiko.Ed25519Key.from_private_key_file(he.pem_path)
                    except Exception:
                        key = None

                kwargs = dict(hostname=str(he.host).strip(), username=he.ssh_user, timeout=300)
                if key:
                    kwargs["pkey"] = key
                else:
                    kwargs["key_filename"] = he.pem_path

                print(f"[BG] SSH connect kwargs for {he.host}: {kwargs}")
                ssh_client.connect(**kwargs)

                # Non-interactive install: update repo, then dpkg -i, then apt-get -f install
                install_cmd = (
                    "sudo /usr/bin/env DEBIAN_FRONTEND=noninteractive /bin/sh -c "
                    f"\"set -e; apt-get update -y || true; "
                    f"if ls {remote_dir}/*.deb >/dev/null 2>&1; then "
                    f"dpkg -i {remote_dir}/*.deb || true; fi; "
                    f"/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get -y -f install || true\""
                )

                print(f"[BG] Running install cmd on {he.host}: {install_cmd}")
                stdin, stdout, stderr = ssh_client.exec_command(install_cmd, timeout=1800)
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                ssh_client.close()

                print(f"[BG] STDOUT for {he.host}:\n{out[:2000]}")
                print(f"[BG] STDERR for {he.host}:\n{err[:2000]}")

                # Decide install success: no 'error' text and dpkg/apt stderr empty-ish
                ok_install = ("error" not in (out + err).lower()) and ("dependency problems" not in (out + err).lower())
                host_summary["install"] = {"ok": ok_install, "stdout": out, "stderr": err}

                he.status = "success" if ok_install else "failed"

                # full output kept in PatchLog; host.message kept short for UI
                full_msg = (out or "") + ("\n\nSTDERR:\n" + err if err else "")
                short_msg = "Patched Succesfully" if ok_install else "failed"  # short value for the table

                he.status = "success" if ok_install else "failed"
                he.message = short_msg
                he.last_patched = datetime.utcnow()
                db.session.add(he)

                # store full debug output in PatchLog (so Log History shows full output)
                log = PatchLog(
                    upload_id=current_upload_id if current_upload_id else he.upload_id,
                    host_id=he.id,
                    host=he.host,
                    action="Patch",
                    status="success" if ok_install else "failed",
                    message=full_msg[:4000],   # store full log in PatchLog (truncate to DB size)
                    user=username
                )
                db.session.add(log)
                db.session.commit()


                print(f"[BG] Host {he.host} patch {'succeeded' if ok_install else 'FAILED'}")

            except Exception as e:
                tb = traceback.format_exc()
                print(f"[BG] Exception while patching host {hid}: {e}\n{tb}")
                try:
                    he = HostEntry.query.get(int(hid))
                    if he:
                        he.status = "failed"
                        he.message = str(e)[:1900]
                        he.last_checked = datetime.utcnow()
                        db.session.add(he)
                        log = PatchLog(
                            upload_id=current_upload_id if current_upload_id else (he.upload_id if he else None),
                            host_id=he.id if he else None,
                            host=he.host if he else str(hid),
                            action="Patch",
                            status="failed",
                            message=str(e)[:1900],
                            user=username
                        )
                        db.session.add(log)
                        db.session.commit()
                except Exception as e2:
                    print(f"[BG] Failed to write DB record for failed host {hid}: {e2}")

                host_summary["error"] = str(e)

            finally:
                summary["hosts"].append(host_summary)

        # final summary save (try)
        try:
            summary_path = os.path.join(packages_path, f"trigger_patch_summary_{ts}.json")
            with open(summary_path, "w") as fh:
                json.dump(summary, fh, indent=2)
            print(f"[BG] Saved summary to {summary_path}")
        except Exception as e:
            print(f"[BG] Failed to save summary JSON: {e}")






@app.route("/trigger_patch", methods=["POST"])
@login_required
def trigger_patch():
    host_ids = request.form.getlist("host_ids[]")
    if not host_ids:
        return jsonify({"error": "host_ids[] required"}), 400

    current_upload_id = session.get("current_upload_id")
    if not current_upload_id:
        any_host = HostEntry.query.get(int(host_ids[0])) if host_ids else None
        if any_host and any_host.upload_id:
            current_upload_id = any_host.upload_id

    # validate packages dir quickly
    packages_path = PACKAGES_DIR
    if not os.path.isdir(packages_path):
        return jsonify({"error": f"Packages folder not found at {packages_path}"}), 400

    deb_files = [
        os.path.join(packages_path, f)
        for f in os.listdir(packages_path)
        if f.endswith(".deb") and os.path.isfile(os.path.join(packages_path, f))
    ]
    if not deb_files:
        return jsonify({"error": "No .deb files found in Packages/"}), 400

    # quick host validation: ensure exist and have ssh details
    for hid in host_ids:
        he = HostEntry.query.get(int(hid))
        if not he:
            return jsonify({"error": f"Host id {hid} not found"}), 400
        if not he.ssh_user or not he.pem_path:
            return jsonify({"error": f"Host {he.host} missing ssh_user/pem_path"}), 400

    # spawn background thread
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    username = session.get("username", "unknown")

    thread = threading.Thread(target=do_patch_job, args=(host_ids, current_upload_id, packages_path, deb_files, username, ts))
    thread.daemon = True
    thread.start()

    # return HTTP 202 Accepted — client shouldn't wait for the job
    return jsonify({"status": "accepted", "ts": ts}), 202






"""


@app.route("/trigger_rollback", methods=["POST"])
@login_required
def trigger_rollback():
    host_ids = request.form.getlist("host_ids[]")
    if not host_ids:
        return jsonify({"error": "host_ids[] required"}), 400

    current_upload_id = session.get("current_upload_id")
    if not current_upload_id:
        return jsonify({"error": "No current upload selected"}), 400

    results = []

    # only allow rollback for patched
    for hid in host_ids:
        he = HostEntry.query.get(int(hid))
        if not he or he.upload_id != current_upload_id:
            return jsonify({"error": f"Host id {hid} not part of current upload"}), 400
        if he.status != "patched":
            return jsonify({"error": f"Host {he.host} not patched. Cannot rollback."}), 400

    # ubuntu rollback logic
    for hid in host_ids:
        he = HostEntry.query.get(int(hid))

        cmd = "sudo apt-get install --reinstall $(apt-cache policy | grep Installed | awk '{print $2}' | sed 's/)//')"
        res = run_patch_on_host(he.host, he.ssh_user, he.pem_path, command=cmd)

        he.status = "connected" if res["ok"] else "failed"
        he.message = f"Rollback: {res['msg']}"
        he.last_checked = datetime.utcnow()
        db.session.add(he)

        log = PatchLog(
            upload_id=current_upload_id,
            host_id=he.id,
            host=he.host,
            action="Rollback",            # <<<<< FIXED here
            status="success" if res["ok"] else "failed",
            message=res["msg"]
        )
        db.session.add(log)

        results.append({"id": he.id, "host": he.host, "ok": res["ok"], "msg": he.message})

    db.session.commit()
    return jsonify({"results": results})


"""

@app.route("/inventory_check", methods=["POST"])
@login_required
def inventory_check():
    current_upload_id = session.get("current_upload_id")
    if not current_upload_id:
        return jsonify({"error": "No active upload"}), 400

    hosts = HostEntry.query.filter_by(upload_id=current_upload_id).all()
    results = []
    for he in hosts:
        res = check_ssh_connectivity(he.host, he.ssh_user, he.pem_path)
        he.status = "connected" if res["ok"] else "failed"
        he.message = res["msg"]
        he.last_checked = datetime.utcnow()
        db.session.add(he)
        results.append({"id": he.id, "status": he.status, "msg": he.message})
    db.session.commit()
    return jsonify({"results": results})



# -----------------------
# Log History - all previous logs
# -----------------------
@app.route("/log_history", methods=["GET"])
@login_required
def log_history():
    # render a page which can call /api/logs or receive logs server-side
    return render_template("log_history.html", username=session.get("username"))

@app.route("/api/logs", methods=["GET"])
@login_required
def api_logs():
    logs = PatchLog.query.order_by(PatchLog.created_at.desc()).limit(200).all()
    out = []
    for l in logs:
        out.append({
            "id": l.id,
            "upload_id": l.upload_id,
            "host_id": l.host_id,
            "host": l.host,
            "action": l.action,
            "status": l.status,
            "message": l.message,
            "user": l.user,
            "created_at": l.created_at.isoformat()
        })
    return jsonify(out)


@app.route("/api/host_status", methods=["GET"])
@login_required
def api_host_status():
    """
    Return status and message for a list of host IDs.
    GET params: host_ids[] e.g. /api/host_status?host_ids[]=1&host_ids[]=2
    Response: { results: [{ id, status, message }, ...] }
    """
    host_ids = request.args.getlist("host_ids[]")
    results = []
    for hid in host_ids:
        try:
            he = HostEntry.query.get(int(hid))
            if not he:
                results.append({"id": hid, "status": "unknown", "message": "host not found"})
            else:
                # return the DB value as-is (string), and message
                results.append({
                    "id": he.id,
                    "status": (he.status or "").strip(),
                    "message": (he.message or "")
                })
        except Exception as e:
            # don't leak internal stack traces to client; return error text
            results.append({"id": hid, "status": "error", "message": str(e)})
    return jsonify({"results": results})



# -----------------------
# Stats Endpoint (global + current upload)
# -----------------------
@app.route("/stats", methods=["GET"])
@login_required
def stats():
    total = HostEntry.query.count()
    connected = HostEntry.query.filter_by(status="connected").count()
    failed = HostEntry.query.filter_by(status="failed").count()
    patched = HostEntry.query.filter_by(status="patched").count()
    pending = HostEntry.query.filter_by(status="pending").count()

    current_upload_id = session.get("current_upload_id")
    upload_stats = {}
    if current_upload_id:
        u = Upload.query.get(current_upload_id)
        if u:
            total_u = HostEntry.query.filter_by(upload_id=current_upload_id).count()
            con_u = HostEntry.query.filter_by(upload_id=current_upload_id, status="connected").count()
            fail_u = HostEntry.query.filter_by(upload_id=current_upload_id, status="failed").count()
            pat_u = HostEntry.query.filter_by(upload_id=current_upload_id, status="patched").count()
            pend_u = HostEntry.query.filter_by(upload_id=current_upload_id, status="pending").count()
            upload_stats = {"upload_id": current_upload_id, "filename": u.filename,
                            "total": total_u, "connected": con_u, "failed": fail_u, "patched": pat_u, "pending": pend_u}

    return jsonify({
        "total": total,
        "connected": connected,
        "failed": failed,
        "patched": patched,
        "pending": pending,
        "current_upload": upload_stats
    })

# =======================
# Initialize DB if missing
# =======================
with app.app_context():
    db.create_all()


# --- Run ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8501, debug=True)