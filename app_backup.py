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


# Absolute path for Packages folder
PACKAGES_DIR = "/home/KnfUser/Packages"

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
    status = db.Column(db.String(32), default="pending")  # pending / connected / failed / patched
    message = db.Column(db.String(1024), nullable=True)
    last_checked = db.Column(db.DateTime, nullable=True)
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
        flash(f"Servers are successfully Onboarded. Navigate to Patch management for further Actions", "success")
        return redirect(url_for("dashboard"))

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


# app.py — DEBUG VERSION of TRIGGER PATCH
@app.route("/trigger_patch", methods=["POST"])
@login_required
def trigger_patch():
    print("\n==================== TRIGGER PATCH START ====================")

    host_ids = request.form.getlist("host_ids[]")
    if not host_ids:
        print("[DEBUG] No host_ids received in form data.")
        return jsonify({"error": "host_ids[] required"}), 400

    # --- Determine upload_id (current or fallback from host) ---
    current_upload_id = session.get("current_upload_id")
    if not current_upload_id:
        any_host = HostEntry.query.get(int(host_ids[0])) if host_ids else None
        if any_host and any_host.upload_id:
            current_upload_id = any_host.upload_id
            print(f"[DEBUG] Derived upload_id from host: {current_upload_id}")
        else:
            current_upload_id = None
            print("[DEBUG] No current_upload_id found and could not derive from host.")

    # --- Check Packages folder ---
    packages_path = PACKAGES_DIR
    print(f"[DEBUG] Packages folder path: {packages_path}")
    if not os.path.isdir(packages_path):
        print("[DEBUG] ERROR: Packages folder not found.")
        return jsonify({"error": f"Packages folder not found at {packages_path}"}), 400

    # --- Gather .deb files ---
    deb_files = [
        os.path.join(packages_path, f)
        for f in os.listdir(packages_path)
        if f.endswith(".deb") and os.path.isfile(os.path.join(packages_path, f))
    ]
    print(f"[DEBUG] Found {len(deb_files)} .deb files: {[os.path.basename(f) for f in deb_files]}")
    if not deb_files:
        return jsonify({"error": "No .deb files found in Packages/"}), 400

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    summary = {"ts": ts, "packages_path": packages_path, "hosts": []}
    results = []

    # --- Validate hosts ---
    for hid in host_ids:
        he = HostEntry.query.get(int(hid))
        if not he:
            print(f"[DEBUG] Host ID {hid} not found in DB.")
            return jsonify({"error": f"Host id {hid} not found"}), 400
        if he.status not in ("connected", "patched", "failed"):
            print(f"[DEBUG] Host {he.host} not ready (status: {he.status})")
            return jsonify({"error": f"Host {he.host} not ready for patching"}), 400

    # --- Start patch per host ---
    for hid in host_ids:
        he = HostEntry.query.get(int(hid))
        host_summary = {"id": he.id, "host": he.host}
        print(f"\n[DEBUG] ==== Starting patch for host {he.host} (ID: {he.id}) ====")

        try:
            remote_dir = os.path.join("/tmp/controller_patches", f"packages_{ts}_{he.id}")
            print(f"[DEBUG] Remote directory: {remote_dir}")

            # 1️⃣ SFTP upload step
            print(f"[DEBUG] Attempting SFTP upload to {he.host} ...")
            ok_up, up_details = sftp_upload_files_with_pem(
                he.host, he.ssh_user, he.pem_path, deb_files, remote_dir
            )
            print(f"[DEBUG] SFTP result for {he.host}: {up_details}")

            host_summary["uploaded"] = up_details.get("uploaded", [])
            if not ok_up:
                raise Exception(up_details.get("error") or "SFTP upload failed")

            # 2️⃣ SSH + Installation step
            print(f"[DEBUG] Connecting via SSH to install packages on {he.host} ...")
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            key = None
            try:
                key = paramiko.RSAKey.from_private_key_file(he.pem_path)
                print("[DEBUG] Loaded RSA private key successfully.")
            except Exception:
                try:
                    key = paramiko.Ed25519Key.from_private_key_file(he.pem_path)
                    print("[DEBUG] Loaded Ed25519 private key successfully.")
                except Exception as e:
                    print(f"[DEBUG] Failed to load PEM key: {e}")
                    key = None

            kwargs = dict(hostname=str(he.host).strip(), username=he.ssh_user, timeout=30)
            if key:
                kwargs["pkey"] = key
            else:
                kwargs["key_filename"] = he.pem_path

            print(f"[DEBUG] SSH connect kwargs: {kwargs}")
            ssh_client.connect(**kwargs)
            print(f"[DEBUG] Connected successfully to {he.host}")

            install_cmd = (
                f"sudo /bin/sh -c 'set -e; "
                f"if ls {remote_dir}/*.deb >/dev/null 2>&1; then "
                f"dpkg -i {remote_dir}/*.deb || true; fi; "
                f"apt-get -y -f install || true'"
            )
            print(f"[DEBUG] Running install command: {install_cmd}")
            stdin, stdout, stderr = ssh_client.exec_command(install_cmd, timeout=300)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            ssh_client.close()

            print(f"[DEBUG] STDOUT for {he.host}:\n{out}")
            print(f"[DEBUG] STDERR for {he.host}:\n{err}")

            ok_install = ("error" not in (out + err).lower())
            host_summary["install"] = {"ok": ok_install, "stdout": out, "stderr": err}

            # 3️⃣ DB + log updates
            he.status = "patched" if ok_install else "failed"
            he.message = "patched" if ok_install else (err[:1000] or "install failed")
            he.last_checked = datetime.utcnow()
            db.session.add(he)

            log = PatchLog(
                upload_id=current_upload_id if current_upload_id else he.upload_id,
                host_id=he.id,
                host=he.host,
                action="Patch",
                status="success" if ok_install else "failed",
                message=he.message,
            )
            db.session.add(log)
            results.append({"id": he.id, "host": he.host, "ok": ok_install, "msg": he.message})

            print(f"[DEBUG] Host {he.host} patch {'succeeded' if ok_install else 'FAILED'}")

        except Exception as e:
            msg = str(e)
            print(f"[DEBUG] Trigger patch failed for {he.host}: {msg}")

            host_summary["error"] = msg
            he.status = "failed"
            he.message = msg[:1000]
            he.last_checked = datetime.utcnow()
            db.session.add(he)

            log = PatchLog(
                upload_id=current_upload_id if current_upload_id else he.upload_id,
                host_id=he.id,
                host=he.host,
                action="Patch",
                status="failed",
                message=msg,
            )
            db.session.add(log)
            results.append({"id": he.id, "host": he.host, "ok": False, "msg": msg})

        finally:
            summary["hosts"].append(host_summary)
            print(f"[DEBUG] Finished host {he.host}")

    db.session.commit()

    # Save summary JSON for audit
    try:
        with open(os.path.join(packages_path, f"trigger_patch_summary_{ts}.json"), "w") as fh:
            json.dump(summary, fh, indent=2)
        print(f"[DEBUG] Saved summary JSON to {packages_path}")
    except Exception as e:
        print(f"[DEBUG] Failed to save summary JSON: {e}")

    print("==================== TRIGGER PATCH END ====================\n")
    return jsonify({"results": results})









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
    app.run(host="0.0.0.0", port=8501, debug=True)