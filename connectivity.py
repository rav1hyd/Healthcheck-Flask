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