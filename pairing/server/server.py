#!/usr/bin/env python3
import json
import os
import sys
import time
import threading
from pathlib import Path
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from spake2 import SPAKE2_A, SPAKE2_B

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.crypto import *

app = Flask(__name__)
app.secret_key = hashlib.sha256(os.urandom(32)).hexdigest()

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

PENDING_FILE = DATA_DIR / "pending.json"
_lock = threading.Lock()

pending = {}

PAIRING_TIMEOUT = 600  # 10 min


def _load():
    global pending
    if PENDING_FILE.exists():
        pending = json.loads(PENDING_FILE.read_text())


def _save():
    PENDING_FILE.write_text(json.dumps(pending, indent=2, ensure_ascii=False))


def _cleanup():
    now = time.time()
    with _lock:
        gone = [cid for cid, e in pending.items()
                if e.get("status") != "paired"
                and now - e.get("created_at", 0) > PAIRING_TIMEOUT]
        for cid in gone:
            del pending[cid]
        if gone:
            _save()


@app.route("/admin", methods=["GET"])
def admin_index():
    _cleanup()
    with _lock:
        now = time.time()
        pending_list = []
        paired_list = []
        for cid, e in pending.items():
            s = e.get("status", "?")
            age = f"{int(now - e.get('created_at', now))}s"
            entry = {"client_id": cid, "status": s, "age": age}
            has_pin = bool(e.get("pin"))
            entry["pin_entered"] = has_pin
            if s == "paired":
                paired_list.append(entry)
            else:
                pending_list.append(entry)
    return render_template("admin.html", pending=pending_list, paired=paired_list)


@app.route("/admin/unpair/<client_id>", methods=["POST"])
def admin_unpair(client_id):
    cid = normalize_code(client_id)
    with _lock:
        if cid not in pending or pending[cid].get("status") != "paired":
            flash(f"Client {cid} nicht gefunden oder nicht gekoppelt.", "error")
            return redirect(url_for("admin_index"))
        del pending[cid]
        _save()
    flash(f"Pairing zu {cid} aufgehoben.", "success")
    return redirect(url_for("admin_index"))


@app.route("/admin/pair", methods=["POST"])
def admin_pair():
    code = request.form.get("pairing_code", "").strip()
    try:
        cid, pin = parse_code(code)
    except (ValueError, Exception) as e:
        flash(f"Ungültiger Code: {e}", "error")
        return redirect(url_for("admin_index"))

    with _lock:
        if cid not in pending:
            flash(f"Client {cid} noch nicht registriert.", "error")
            return redirect(url_for("admin_index"))
        e = pending[cid]
        if e.get("status") == "paired":
            flash(f"Client {cid} bereits gekoppelt.", "error")
            return redirect(url_for("admin_index"))
        e["pin"] = pin
        e["status"] = "init"
        for k in ("confirm_key", "session_key", "server_msg"):
            e.pop(k, None)
        _save()

    flash(f"PIN für {cid} gespeichert. Client wird nun koppeln…", "success")
    return redirect(url_for("admin_index"))


@app.route("/api/pair/init", methods=["POST"])
def api_init():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Keine Daten"}), 400
    cid = normalize_code(data.get("client_id", ""))
    if not cid or len(cid) != 8:
        return jsonify({"status": "error", "message": "Ungültige Client-ID"}), 400

    with _lock:
        if cid in pending and pending[cid].get("status") == "paired":
            return jsonify({"status": "error", "message": "Bereits gekoppelt"}), 409
        pending[cid] = {"status": "init", "pin": None, "created_at": time.time()}
        _save()
    return jsonify({"status": "waiting"})


@app.route("/api/pair/status/<client_id>", methods=["GET"])
def api_status(client_id):
    _cleanup()
    cid = normalize_code(client_id)
    with _lock:
        if cid not in pending:
            return jsonify({"status": "error", "message": "Unbekannter Client"}), 404
        e = pending[cid]
        if e.get("status") == "paired":
            return jsonify({"status": "paired"})
        if e.get("pin"):
            return jsonify({"status": "ready"})
        return jsonify({"status": "waiting"})


@app.route("/api/pair/spake2/<client_id>", methods=["POST"])
def api_spake2(client_id):
    cid = normalize_code(client_id)
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Keine Daten"}), 400

    client_msg_hex = data.get("client_msg", "")
    try:
        client_msg = bytes.fromhex(client_msg_hex)
    except ValueError:
        return jsonify({"status": "error", "message": "Ungültiges Format"}), 400

    with _lock:
        if cid not in pending:
            return jsonify({"status": "error", "message": "Unbekannter Client"}), 404
        e = pending[cid]
        if e.get("status") == "paired":
            return jsonify({"status": "paired"})
        if not e.get("pin"):
            return jsonify({"status": "error", "message": "PIN noch nicht eingegeben"}), 400

        pin = e["pin"]
        try:
            server = SPAKE2_B(pin.encode())
            server_msg = server.start()
            spake_key = server.finish(client_msg)
        except Exception as ex:
            return jsonify({"status": "error", "message": f"SPAKE2-Fehler: {ex}"}), 400

        confirm_key = derive_confirm_key(spake_key)
        session_key = derive_session_key(spake_key)
        server_confirm = compute_hmac(
            confirm_key, cid, client_msg, server_msg, "server"
        )

        e["status"] = "spake2"
        e["client_msg"] = client_msg.hex()
        e["confirm_key"] = confirm_key.hex()
        e["session_key"] = session_key.hex()
        e["server_msg"] = server_msg.hex()
        _save()

    return jsonify({
        "status": "ok",
        "server_msg": server_msg.hex(),
        "server_confirm": server_confirm.hex(),
    })


@app.route("/api/pair/verify/<client_id>", methods=["POST"])
def api_verify(client_id):
    cid = normalize_code(client_id)
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Keine Daten"}), 400

    client_confirm_hex = data.get("client_confirm", "")
    try:
        client_confirm = bytes.fromhex(client_confirm_hex)
    except ValueError:
        return jsonify({"status": "error", "message": "Ungültiges Format"}), 400

    with _lock:
        if cid not in pending:
            return jsonify({"status": "error", "message": "Unbekannter Client"}), 404
        e = pending[cid]
        if e.get("status") == "paired":
            return jsonify({"status": "paired"})
        if e.get("status") != "spake2":
            return jsonify({"status": "error", "message": "SPAKE2-Austausch noch nicht erfolgt"}), 400

        confirm_key = bytes.fromhex(e["confirm_key"])
        session_key = bytes.fromhex(e["session_key"])
        server_msg = bytes.fromhex(e["server_msg"])
        client_msg = bytes.fromhex(e.get("client_msg") or data.get("client_msg", ""))

        expected = compute_hmac(confirm_key, cid, client_msg, server_msg, "client")
        if not constant_time_compare(client_confirm, expected):
            return jsonify({
                "status": "error",
                "message": "Client-Authentifizierung fehlgeschlagen",
            }), 403

        e["status"] = "paired"
        e["paired_at"] = time.time()
        _save()

    return jsonify({
        "status": "paired",
        "session_key": session_key.hex(),
    })


def _cleanup_loop():
    while True:
        time.sleep(60)
        try:
            _cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    _load()
    t = threading.Thread(target=_cleanup_loop, daemon=True)
    t.start()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    print(f"Server startet auf {host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
