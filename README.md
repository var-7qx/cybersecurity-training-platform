# MY COLLECTIONS — Local Pentest Training Lab

A realistic personal-collections web app scaffold with 20 synthetic accounts. It is intended for **authorized local practice only**.

## Safety boundary

- Binds to `127.0.0.1` only. Do not change this to `0.0.0.0`.
- Do not port-forward it, deploy it publicly, or expose it to a shared network.
- Use only the synthetic accounts and dummy records created by `seed.py`.
- Never use personal/reused passwords or real personal files.
- The current implementation is a **secure baseline**, not a deliberately vulnerable production app. It includes login, roles, owner-scoped collections, audit logging, and hashed passwords.
- A controlled vulnerability track is specified below. Add one lab at a time, isolated and explicitly enabled; do not weaken the baseline globally.

## Setup — Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python seed.py
python run.py
```

Open `http://127.0.0.1:5000`.

## Setup — Kali Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python seed.py
python run.py
```

Open `http://127.0.0.1:5000` in the same machine.

## Test accounts

`seed.py` creates 20 accounts with synthetic passwords and stores password hashes in SQLite. It writes the plaintext lab-only credential list to `LAB_CREDENTIALS.txt`. That file is ignored by Git. Do not share it.

Roles: admin, manager, editor, user, guest. `admin` is the only administrator.

## Included now

- Login/logout with password hash verification
- Session cookie HTTPOnly and SameSite=Lax
- Generic invalid-login response
- Parameterized SQL queries
- Role-protected admin page
- User-owned collection listing
- Login/logout audit events
- 20 synthetic accounts and sample dummy data
- Loopback-only server startup

## Development specification / planned lab modules

The application is deliberately secure by default. The following modules should be implemented as separate lab exercises, each with a clear reset path and synthetic data:

| Track | Learning objective | Safe lab implementation plan |
|---|---|---|
| Authentication | Password strength, credential stuffing concepts, brute-force defenses | Add a dedicated local-only login challenge with a configurable attempt budget, visible audit events, and a resettable test account. Keep the default login protected. |
| Enumeration | Understand username enumeration | Compare generic vs intentionally different responses in a disposable lab route; never expose real users. |
| Session security | Cookie flags, rotation, expiration, logout invalidation | Add test cases and a session-inspection page that reveals only the current synthetic session. |
| Access control / IDOR | Object ownership checks | Create two synthetic users and compare owner-scoped vs deliberately misconfigured lab endpoints; no real files or records. |
| SQL injection | Query parameterization | Keep main app parameterized; add a separate toy endpoint backed only by a disposable in-memory database and harmless sample rows. |
| XSS | Output encoding and CSP | Add a sandboxed comments page with synthetic content and a paired encoded version. |
| CSRF | Request integrity | Add a state-changing dummy preference form and compare token-protected vs isolated training variant. |
| File upload | Type validation, storage isolation, path handling | Use a dedicated quarantine directory, strict size/type allowlist, random filenames, and dummy text files only. |
| Path traversal | Canonicalization and file boundary checks | Use a toy file-reader endpoint restricted to a disposable fixture directory. |
| Security configuration | Headers, debug mode, secrets, error handling | Add a checklist and automated tests for secure defaults. |

## Brute-force learning boundary

Use a local-only, low-volume test against the synthetic accounts. The goal is to understand why weak passwords, missing throttling, and poor monitoring are dangerous, then validate defenses. Do not point testing tools at third-party systems or accounts. The current baseline does not intentionally disable rate limiting because the dedicated training challenge has not yet been added.

## Reset

Stop the server, then delete `instance/my_collections.db` and run:

```bash
python seed.py
```

The credential file will be regenerated.

## Important

This starter implementation is not yet a complete file-upload/gallery product and does not yet contain all planned vulnerability exercises. It is the foundation: account system, roles, sample collections, audit trail, and a written roadmap.
