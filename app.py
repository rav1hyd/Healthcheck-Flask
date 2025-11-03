import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import yaml
import pandas as pd
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import paramiko
import socket

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
    status = db.Column(db.String(32), default="pending")  # pending / connected / failed / patched
    message = db.Column(db.String(1024), nullable=True)
    last_checked = db.Column(db.DateTime, nullable=True)
    upload = db.relationship("Upload", back_populates="hosts")

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
    """Find first matching column name from given list of candidates."""
    for name in possible_names:
        for c in columns:
            if name.lower() in c.lower():
                return c
    return None

def check_ssh_connectivity(host, username, pem_path, timeout=5):
    """Try SSH connection using paramiko (returns dict)."""
    try:
        if not pem_path or not os.path.exists(pem_path):
            return {"host": host, "ok": False, "msg": f"PEM not found or not provided: {pem_path}"}

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
        connect_kwargs = dict(hostname=str(host).strip(), username=username, timeout=timeout)
        if key:
            connect_kwargs["pkey"] = key
        else:
            connect_kwargs["key_filename"] = pem_path

        client.connect(**connect_kwargs)
        # light check: run echo
        stdin, stdout, stderr = client.exec_command("echo ok", timeout=timeout)
        out = stdout.read().decode().strip()
        client.close()
        if out == "ok":
            return {"host": host, "ok": True, "msg": "Connected"}
        else:
            return {"host": host, "ok": True, "msg": f"Connected (echo returned: {out})"}
    except paramiko.AuthenticationException:
        return {"host": host, "ok": False, "msg": "Authentication failed"}
    except (paramiko.SSHException, socket.error, socket.timeout) as e:
        return {"host": host, "ok": False, "msg": f"SSH error: {str(e)}"}
    except Exception as e:
        return {"host": host, "ok": False, "msg": f"Error: {str(e)}"}

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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == AUTH.get("username") and password == AUTH.get("password"):
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
    columns = []
    current_upload_id = session.get("current_upload_id")

    # POST = upload new Excel
    if request.method == "POST":
        if "file" not in request.files or request.files["file"].filename == "":
            flash("Please select a valid Excel file (.xls or .xlsx)", "warning")
            return redirect(url_for("dashboard"))

        file = request.files["file"]
        if not allowed_file(file.filename):
            flash("Invalid file format. Upload .xls or .xlsx only.", "danger")
            return redirect(url_for("dashboard"))

        filename = file.filename
        try:
            df = pd.read_excel(BytesIO(file.read()))
        except Exception as e:
            flash(f"Failed to read Excel file: {e}", "danger")
            return redirect(url_for("dashboard"))

        rows, cols = df.shape
        columns = df.columns.tolist()
        host_col = find_column(columns, ["host", "ip", "hostname", "server", "address"])
        ssh_col = find_column(columns, ["ssh_user", "username", "user"])
        pem_col = find_column(columns, ["pem_path", "key_path", "keyfile", "pem", "key"])

        if not host_col:
            flash("No host column found in the Excel.", "warning")
            return redirect(url_for("dashboard"))

        # create Upload entry
        upload = Upload(filename=filename, rows=rows, cols=cols)
        db.session.add(upload)
        db.session.flush()  # get ID

        # insert hosts
        for _, r in df.iterrows():
            host_val = str(r.get(host_col, "")).strip()
            if not host_val:
                continue
            ssh_user = str(r.get(ssh_col, "")).strip() if ssh_col else None
            pem_path = str(r.get(pem_col, "")).strip() if pem_col else None
            db.session.add(HostEntry(upload_id=upload.id, host=host_val,
                                     ssh_user=ssh_user or None, pem_path=pem_path or None))
        db.session.commit()

        # ✅ store session id and redirect to patch management directly
        session["current_upload_id"] = upload.id
        flash(f"File '{filename}' uploaded successfully. Set as current upload (ID={upload.id})", "success")
        return redirect(url_for("patch_management"))

    # GET = show preview of current upload if exists
    if current_upload_id:
        upload = Upload.query.get(current_upload_id)
        if upload:
            hosts = HostEntry.query.filter_by(upload_id=current_upload_id).limit(50).all()
            if hosts:
                df_preview = pd.DataFrame([
                    {"Host": h.host, "SSH User": h.ssh_user or "", "PEM": h.pem_path or "", "Status": h.status or "pending"}
                    for h in hosts
                ])
                preview_html = df_preview.to_html(classes="table table-striped table-sm", index=False, escape=False)
            filename = upload.filename
            rows, cols = upload.rows, upload.cols

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        preview_table=preview_html,
        filename=filename,
        rows=rows,
        cols=cols,
        columns=columns,
        current_upload_id=current_upload_id
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
            results.append({"id": he.id, "host": he.host, "ok": False, "msg": he.message})
            continue

        res = check_ssh_connectivity(he.host, he.ssh_user, he.pem_path)
        he.status = "connected" if res["ok"] else "failed"
        he.message = res["msg"]
        he.last_checked = datetime.utcnow()
        db.session.add(he)
        db.session.commit()
        results.append({"id": he.id, "host": he.host, "ok": res["ok"], "msg": res["msg"]})
    return jsonify({"results": results})

@app.route("/trigger_patch", methods=["POST"])
@login_required
def trigger_patch():
    host_ids = request.form.getlist("host_ids[]")
    command = request.form.get("command", "echo patched")

    if not host_ids:
        return jsonify({"error": "host_ids[] required"}), 400

    current_upload_id = session.get("current_upload_id")
    if not current_upload_id:
        return jsonify({"error": "No current upload selected"}), 400

    results = []
    for hid in host_ids:
        he = HostEntry.query.get(int(hid))
        if not he or he.upload_id != current_upload_id:
            continue
        if he.status != "connected":
            results.append({"id": he.id, "host": he.host, "ok": False, "msg": "Host not connected. Run check first."})
            continue

        res = run_patch_on_host(he.host, he.ssh_user, he.pem_path, command=command)
        he.status = "patched" if res["ok"] else "failed"
        he.message = res["msg"]
        he.last_checked = datetime.utcnow()
        db.session.add(he)

        log = PatchLog(upload_id=current_upload_id, host_id=he.id, host=he.host,
                       action=command, status="success" if res["ok"] else "failed", message=res["msg"])
        db.session.add(log)

        results.append({"id": he.id, "host": he.host, "ok": res["ok"], "msg": res["msg"]})
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
            "created_at": l.created_at.isoformat()
        })
    return jsonify(out)

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
    app.run(debug=True)
