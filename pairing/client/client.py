#!/usr/bin/env python3
import argparse
import json
import sys
import time
from pathlib import Path
import requests
from spake2 import SPAKE2_A

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.crypto import *

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = DATA_DIR / "pairing_state.json"


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"paired": False}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))
    STATE_FILE.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description="VPN Pairing Client (SPAKE2)")
    parser.add_argument("server_url", help="Server-URL (z.B. http://10.0.0.1:5000)")
    parser.add_argument("--force", action="store_true", help="Neues Pairing erzwingen")
    args = parser.parse_args()

    server = args.server_url.rstrip("/")

    state = load_state()
    if state.get("paired") and not args.force:
        print("[i] Bereits gekoppelt (--force für neues Pairing).")
        print(f"[i] Session Key: {state.get('session_key', '?')}")
        return 0

    if args.force:
        save_state({"paired": False})

    client_id = generate_id()
    pin = generate_pin()
    print()
    print("#" * 60)
    print(f"  Client-ID:  {client_id}")
    print(f"  PIN:        {pin}")
    print(f"  Pairing:    {client_id}-{pin}")
    print("#" * 60)
    print(f"  Code in Server-UI eingeben: {server}/admin")
    print()

    try:
        r = requests.post(f"{server}/api/pair/init",
                          json={"client_id": client_id}, timeout=10)
        if r.status_code == 409:
            print("[!] Bereits auf Server gekoppelt. Verwende --force.")
            return 1
        r.raise_for_status()
        print(f"[*] Registriert: {r.json()['status']}")
    except requests.RequestException as e:
        print(f"[FEHLER] {e}")
        return 1

    print("[*] Warte auf PIN-Eingabe (Admin muss Code im Web-UI eingeben)…")
    t = 0
    paired = False
    session_key = None

    while not paired:
        try:
            r = requests.get(f"{server}/api/pair/status/{client_id}", timeout=10)
            r.raise_for_status()
            data = r.json()
        except requests.RequestException as e:
            print(f"\n[FEHLER] {e}")
            time.sleep(3)
            continue

        if data["status"] == "paired":
            print("\n[i] Bereits gekoppelt.")
            break

        if data["status"] == "error":
            print(f"\n[FEHLER] {data.get('message', '?')}")
            return 1

        if data["status"] == "ready":
            print(f"\n[+] PIN akzeptiert – starte SPAKE2-Austausch …")

            client = SPAKE2_A(pin.encode())
            client_msg = client.start()

            try:
                r2 = requests.post(f"{server}/api/pair/spake2/{client_id}",
                                   json={"client_msg": client_msg.hex()},
                                   timeout=10)
                r2.raise_for_status()
                resp = r2.json()
            except requests.RequestException as e:
                print(f"[FEHLER] SPAKE2-Request: {e}")
                return 1

            if resp.get("status") == "error":
                print(f"[FEHLER] {resp.get('message', '?')}")
                return 1

            if resp.get("status") == "paired":
                print("[i] Server meldet bereits gekoppelt.")
                break

            server_msg = bytes.fromhex(resp["server_msg"])
            server_confirm = bytes.fromhex(resp["server_confirm"])

            spake_key = client.finish(server_msg)
            confirm_key = derive_confirm_key(spake_key)
            session_key = derive_session_key(spake_key)

            expected = compute_hmac(confirm_key, client_id,
                                    client_msg, server_msg, "server")
            if not constant_time_compare(server_confirm, expected):
                print("[FEHLER] Server-Authentifizierung fehlgeschlagen!")
                print("        Falscher PIN eingegeben?")
                return 1

            print("[+] Server authentifiziert. Sende Bestätigung …")

            client_confirm = compute_hmac(confirm_key, client_id,
                                          client_msg, server_msg, "client")

            try:
                r3 = requests.post(f"{server}/api/pair/verify/{client_id}",
                                   json={
                                       "client_confirm": client_confirm.hex(),
                                       "client_msg": client_msg.hex(),
                                   },
                                   timeout=10)
                r3.raise_for_status()
                result = r3.json()
            except requests.RequestException as e:
                print(f"[FEHLER] Verify: {e}")
                return 1

            if result.get("status") == "paired":
                print("[+] Pairing erfolgreich!")
                paired = True
            else:
                print(f"[FEHLER] {result}")
                return 1

        else:
            if t % 30 == 0:
                print(f"\r[*] Warte … ({t}s)", end="", flush=True)
            else:
                print(".", end="", flush=True)
            t += 1
            time.sleep(1)

    if paired or data.get("status") == "paired":
        if not session_key:
            session_key = bytes.fromhex(result.get("session_key", ""))
        save_state({
            "paired": True,
            "client_id": client_id,
            "session_key": session_key.hex(),
        })
        print()
        print("=" * 60)
        print("  Gemeinsames Secret (Session Key)")
        print("=" * 60)
        print(f"  Hex:      {session_key.hex()}")
        print(f"  Base64:   {__import__('base64').b64encode(session_key).decode()}")
        print()
        print("  Aus diesem Key können später WireGuard-Schlüssel")
        print("  oder ein PSK abgeleitet werden.")
        print("=" * 60)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
