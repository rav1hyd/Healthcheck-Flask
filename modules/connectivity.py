import os, socket, paramiko


def check_ssh_connectivity(host, username, pem_path, timeout=5):
    try:
        if not pem_path or not os.path.exists(pem_path):
            return {"host": host, "ok": False, "msg": "PEM file missing / not found"}

        key = None
        try:
            key = paramiko.RSAKey.from_private_key_file(pem_path)
        except:
            try:
                key = paramiko.Ed25519Key.from_private_key_file(pem_path)
            except:
                key = None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs = dict(hostname=str(host).strip(), username=username, timeout=timeout)
        if key:
            kwargs["pkey"] = key
        else:
            kwargs["key_filename"] = pem_path

        client.connect(**kwargs)
        stdin, stdout, stderr = client.exec_command("echo ok", timeout=timeout)
        out = stdout.read().decode().strip()
        client.close()

        if out == "ok":
            return {"host": host, "ok": True, "msg": "Connection Successful"}
        return {"host": host, "ok": True, "msg": "Connected"}

    except socket.timeout:
        return {"host": host, "ok": False, "msg": "Connection Timeout (host unavailable)"}
    except paramiko.AuthenticationException:
        return {"host": host, "ok": False, "msg": "SSH Authentication Failed"}
    except paramiko.ssh_exception.NoValidConnectionsError:
        return {"host": host, "ok": False, "msg": "Port 22 Not Reachable (FW)"}
    except Exception as e:
        return {"host": host, "ok": False, "msg": f"{str(e)}"}


def sftp_upload_files_with_pem(host, username, pem_path, local_files, remote_dir, timeout=30):
    """
    Connects via paramiko (using PEM like check_ssh_connectivity) and uploads local_files to remote_dir.
    Returns (ok: bool, details: dict)
    details = {uploaded: [remote_paths], stdout: "", stderr: "", error: str}
    """
    details = {"uploaded": [], "stdout": "", "stderr": "", "error": None}
    client = None
    try:
        if not pem_path or not os.path.exists(pem_path):
            details["error"] = f"PEM file missing: {pem_path}"
            return False, details

        # Load PEM key (RSA or Ed25519)
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

        kwargs = dict(hostname=str(host).strip(), username=username, timeout=timeout)
        if key:
            kwargs["pkey"] = key
        else:
            kwargs["key_filename"] = pem_path

        # Connect to target machine
        client.connect(**kwargs)
        sftp = client.open_sftp()

        # Ensure remote_dir exists
        try:
            sftp.stat(remote_dir)
        except IOError:
            parts = remote_dir.strip("/").split("/")
            path = ""
            for p in parts:
                path += "/" + p
                try:
                    sftp.stat(path)
                except IOError:
                    sftp.mkdir(path)
                    try:
                        sftp.chmod(path, 0o700)
                    except Exception:
                        pass

        # Upload all files
        for lf in local_files:
            basename = os.path.basename(lf)
            remote_path = os.path.join(remote_dir, basename)
            sftp.put(lf, remote_path)
            try:
                sftp.chmod(remote_path, 0o600)
            except Exception:
                pass
            details["uploaded"].append(remote_path)

        sftp.close()
        client.close()
        return True, details

    except Exception as e:
        details["error"] = str(e)
        if client:
            try:
                client.close()
            except Exception:
                pass
        return False, details