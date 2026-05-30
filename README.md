# SPAKE2 VPN Pairing

Kryptographisch abgesichertes Pairing zwischen einem VPN-Client und -Server mittels **SPAKE2** (PAKE) über ein HTTP-basiertes Protokoll.

## Funktionsprinzip

Der Client generiert eine **8-stellige ID** und einen **6-stelligen PIN** (beide aus `A–Z0–9`). Der Nutzer überträgt die Kombination `ID-PIN` manuell (out-of-band) in die Admin-Oberfläche des Servers. Anschließend führen Client und Server einen **SPAKE2-Austausch** durch:

```
Client (Alice)                     Server (Bob)
       │                                │
       │── POST /api/pair/init ────────>│  ID registrieren
       │<─── {status: "waiting"} ──────│
       │                                │  Admin gibt ID-PIN im Web-UI ein
       │── GET /api/pair/status ───────>│  pollt
       │<─── {status: "ready"} ────────│
       │                                │
       │── POST /api/pair/spake2 ──────>│  SPAKE2_A → client_msg
       │  {client_msg}                  │  SPAKE2_B → server_msg
       │<─── {server_msg,               │  + .finish(client_msg) → shared_key
       │       server_confirm} ────────│  + server_confirm = HMAC(confirm_key, …)
       │                                │
       │client.finish(server_msg)       │
       │→ shared_key (gleich)           │
       │verify server_confirm           │
       │                                │
       │── POST /api/pair/verify ──────>│
       │  {client_confirm}              │  verify client_confirm
       │<─── {status: "paired"} ───────│  status → "paired"
       │                                │
```

Beide Seiten leiten aus dem SPAKE2-Output denselben **32-Byte Session-Key** ab (HKDF). Der Client überwacht anschließend zyklisch (alle 10s), ob das Pairing auf Serverseite noch besteht – mittels kryptographischer Challenge-Response:

```
Client → Server:  {nonce}
Server → Client:  HMAC(session_key, nonce + client_id)
```

Wird das Pairing vom Admin aufgehoben, löscht der Server den Session-Key; der Client erkennt dies beim nächsten Poll und setzt seinen Status zurück.

## Verzeichnisstruktur

```
pairing/
├── common/
│   └── crypto.py           # PIN/ID-Generierung, HKDF, HMAC
├── server/
│   ├── server.py           # Flask-App (Admin-UI + REST-API)
│   ├── templates/
│   │   └── admin.html      # Admin-Oberfläche
│   └── data/               # Laufzeitdaten (gitignoriert)
├── client/
│   ├── client.py           # CLI-Client (Pairing + Überwachung)
│   └── data/               # Laufzeitdaten (gitignoriert)
├── README.md
└── .gitignore
```

## Installation

```bash
pip install -r pairing/server/requirements.txt
pip install -r pairing/client/requirements.txt
```

## Verwendung

**Server starten:**
```bash
python3 pairing/server/server.py
# → http://0.0.0.0:5000/admin
```

**Client starten:**
```bash
python3 pairing/client/client.py http://SERVER:5000
# Zeigt: Client-ID: ABC12345  PIN: 9X7K2M
```

Den angezeigten Code (`ABC12345-9X7K2M`) in der Admin-Oberfläche eingeben. Der Client koppelt automatisch und überwacht die Verbindung.

## API-Übersicht

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| `POST` | `/api/pair/init` | Client-ID registrieren |
| `GET` | `/api/pair/status/<id>` | Pairing-Status abfragen |
| `POST` | `/api/pair/spake2/<id>` | SPAKE2-Nachricht austauschen |
| `POST` | `/api/pair/verify/<id>` | Gegenseitige Bestätigung |
| `POST` | `/api/pair/verify-session/<id>` | Session-Kryptographisch prüfen |
| `POST` | `/admin/pair` | PIN eingeben |
| `POST` | `/admin/unpair/<id>` | Pairing aufheben |

## Sicherheit

- **SPAKE2** (PAKE) verhindert Offline-Wörterbuchangriffe auf den PIN
- **X25519** für den ephemeren Schlüsselaustausch
- **HKDF** zur Schlüsselableitung (separate Keys für Confirmation und Session)
- **HMAC** zur gegenseitigen Authentisierung (Key-Confirmation)
- Die ständige Session-Verifikation stellt sicher, dass aufgehobene Pairings auf Client-Seite erkannt werden – der Server kann ein Pairing nicht unbemerkt vortäuschen
