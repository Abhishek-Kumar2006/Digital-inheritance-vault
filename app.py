"""
Digital Inheritance Vault - prototype backend (FastAPI + SQLite)

Zero-knowledge design:
  * The browser derives two secrets from the user's password (PBKDF2):
      - an "auth key"  -> sent to the server to log in (server stores only a scrypt hash of it)
      - a "wrap key"   -> never leaves the browser; wraps the random AES-256 master key
  * All record details and uploaded files are encrypted in the browser with AES-256-GCM.
  * This server only ever stores ciphertext. It cannot read your vault.
"""
import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DATA = Path(os.environ.get("VAULT_DATA", BASE / "data"))
FILES = DATA / "files"
DATA.mkdir(exist_ok=True)
FILES.mkdir(exist_ok=True)
DB_PATH = DATA / "vault.db"

KDF_ITERS = 600_000
MAX_FILE = 15 * 1024 * 1024
SESSION_TTL = 60 * 60 * 8
# Used to give unknown emails a stable fake salt so accounts can't be enumerated.
PEPPER = (DATA / "pepper")
if not PEPPER.exists():
    PEPPER.write_bytes(secrets.token_bytes(32))
    PEPPER.chmod(0o600)
PEPPER_KEY = PEPPER.read_bytes()

app = FastAPI(title="Digital Inheritance Vault")


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init():
    with closing(db()) as c:
        c.executescript(
            """
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT,
          kdf_salt TEXT NOT NULL, kdf_iters INTEGER NOT NULL,
          auth_salt TEXT NOT NULL, auth_hash TEXT NOT NULL,
          wrapped_key TEXT NOT NULL, created REAL,
          fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY, user_id INTEGER, expires REAL);
        CREATE TABLE IF NOT EXISTS items(
          id INTEGER PRIMARY KEY, user_id INTEGER, blob TEXT NOT NULL, created REAL, updated REAL);
        CREATE TABLE IF NOT EXISTS files(
          id TEXT PRIMARY KEY, user_id INTEGER, size INTEGER, created REAL);
        CREATE TABLE IF NOT EXISTS activity(
          id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, ts REAL, ip TEXT);
        """
        )


init()


def log(c, uid, action, request: Request):
    ip = request.client.host if request.client else "?"
    c.execute("INSERT INTO activity(user_id,action,ts,ip) VALUES(?,?,?,?)", (uid, action, time.time(), ip))


def b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        raise HTTPException(400, "bad encoding")


def hash_auth(auth_key: bytes, salt: bytes) -> str:
    return hashlib.scrypt(auth_key, salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


class Reg(BaseModel):
    email: str = Field(max_length=200)
    name: str = Field(max_length=100)
    kdf_salt: str
    auth_key: str
    wrapped_key: str


class Login(BaseModel):
    email: str
    auth_key: str


class Blob(BaseModel):
    blob: str = Field(max_length=2_000_000)


def user_from_token(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "not signed in")
    th = hashlib.sha256(authorization[7:].encode()).hexdigest()
    with closing(db()) as c:
        r = c.execute("SELECT user_id, expires FROM sessions WHERE token_hash=?", (th,)).fetchone()
        if not r or r["expires"] < time.time():
            raise HTTPException(401, "session expired")
        return r["user_id"]


@app.post("/api/register")
def register(body: Reg, request: Request):
    email = body.email.strip().lower()
    if "@" not in email or len(email) < 5:
        raise HTTPException(400, "Enter a valid email")
    ak = b64d(body.auth_key)
    if len(ak) != 32:
        raise HTTPException(400, "bad key")
    asalt = secrets.token_bytes(16)
    with closing(db()) as c:
        try:
            cur = c.execute(
                "INSERT INTO users(email,name,kdf_salt,kdf_iters,auth_salt,auth_hash,wrapped_key,created) VALUES(?,?,?,?,?,?,?,?)",
                (email, body.name.strip(), body.kdf_salt, KDF_ITERS, asalt.hex(), hash_auth(ak, asalt), body.wrapped_key, time.time()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "An account with this email already exists")
        log(c, cur.lastrowid, "Vault created", request)
        c.commit()
    return {"ok": True}


@app.get("/api/salt")
def salt(email: str):
    email = email.strip().lower()
    with closing(db()) as c:
        r = c.execute("SELECT kdf_salt,kdf_iters FROM users WHERE email=?", (email,)).fetchone()
    if r:
        return {"kdf_salt": r["kdf_salt"], "kdf_iters": r["kdf_iters"]}
    fake = hmac.new(PEPPER_KEY, email.encode(), hashlib.sha256).digest()[:16]
    return {"kdf_salt": base64.b64encode(fake).decode(), "kdf_iters": KDF_ITERS}


@app.post("/api/login")
def login(body: Login, request: Request):
    email = body.email.strip().lower()
    ak = b64d(body.auth_key)
    with closing(db()) as c:
        u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and u["locked_until"] > time.time():
            raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
        ok = False
        if u:
            ok = hmac.compare_digest(hash_auth(ak, bytes.fromhex(u["auth_salt"])), u["auth_hash"])
        else:
            hash_auth(ak, b"x" * 16)  # equalise timing
        if not ok:
            if u:
                fails = u["fails"] + 1
                lock = time.time() + 300 if fails >= 5 else 0
                c.execute("UPDATE users SET fails=?, locked_until=? WHERE id=?", (0 if lock else fails, lock, u["id"]))
                log(c, u["id"], "Failed sign-in attempt", request)
                c.commit()
            raise HTTPException(401, "Incorrect email or password")
        c.execute("UPDATE users SET fails=0, locked_until=0 WHERE id=?", (u["id"],))
        token = secrets.token_urlsafe(32)
        c.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        c.execute(
            "INSERT INTO sessions VALUES(?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), u["id"], time.time() + SESSION_TTL),
        )
        log(c, u["id"], "Signed in", request)
        c.commit()
        return {"token": token, "name": u["name"], "wrapped_key": u["wrapped_key"]}


@app.post("/api/logout")
def logout(authorization: str = Header(default="")):
    if authorization.startswith("Bearer "):
        with closing(db()) as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(authorization[7:].encode()).hexdigest(),))
            c.commit()
    return {"ok": True}


@app.get("/api/items")
def list_items(uid: int = Depends(user_from_token)):
    with closing(db()) as c:
        rows = c.execute("SELECT id,blob,created,updated FROM items WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/items")
def add_item(body: Blob, request: Request, uid: int = Depends(user_from_token)):
    with closing(db()) as c:
        now = time.time()
        cur = c.execute("INSERT INTO items(user_id,blob,created,updated) VALUES(?,?,?,?)", (uid, body.blob, now, now))
        log(c, uid, "Record added", request)
        c.commit()
        return {"id": cur.lastrowid}


@app.put("/api/items/{iid}")
def edit_item(iid: int, body: Blob, request: Request, uid: int = Depends(user_from_token)):
    with closing(db()) as c:
        cur = c.execute("UPDATE items SET blob=?, updated=? WHERE id=? AND user_id=?", (body.blob, time.time(), iid, uid))
        if not cur.rowcount:
            raise HTTPException(404, "not found")
        log(c, uid, "Record updated", request)
        c.commit()
    return {"ok": True}


@app.delete("/api/items/{iid}")
def del_item(iid: int, request: Request, files: str = "", uid: int = Depends(user_from_token)):
    with closing(db()) as c:
        cur = c.execute("DELETE FROM items WHERE id=? AND user_id=?", (iid, uid))
        if not cur.rowcount:
            raise HTTPException(404, "not found")
        for fid in filter(None, files.split(",")):
            _delete_file(c, fid, uid)
        log(c, uid, "Record deleted", request)
        c.commit()
    return {"ok": True}


def _delete_file(c, fid, uid):
    if not fid.isalnum():
        return
    r = c.execute("DELETE FROM files WHERE id=? AND user_id=?", (fid, uid))
    if r.rowcount:
        (FILES / fid).unlink(missing_ok=True)


@app.post("/api/files")
async def upload_file(request: Request, uid: int = Depends(user_from_token)):
    body = await request.body()
    if not body or len(body) > MAX_FILE + 1024:
        raise HTTPException(413, "File too large (max 15 MB)")
    fid = secrets.token_hex(16)
    (FILES / fid).write_bytes(body)  # ciphertext only
    with closing(db()) as c:
        c.execute("INSERT INTO files VALUES(?,?,?,?)", (fid, uid, len(body), time.time()))
        log(c, uid, "Encrypted file uploaded", request)
        c.commit()
    return {"id": fid}


@app.get("/api/files/{fid}")
def get_file(fid: str, request: Request, uid: int = Depends(user_from_token)):
    with closing(db()) as c:
        r = c.execute("SELECT id FROM files WHERE id=? AND user_id=?", (fid, uid)).fetchone()
        if not r or not fid.isalnum():
            raise HTTPException(404, "not found")
        log(c, uid, "Encrypted file accessed", request)
        c.commit()
    return Response((FILES / fid).read_bytes(), media_type="application/octet-stream")


@app.delete("/api/files/{fid}")
def del_file(fid: str, uid: int = Depends(user_from_token)):
    with closing(db()) as c:
        _delete_file(c, fid, uid)
        c.commit()
    return {"ok": True}


@app.get("/api/activity")
def activity(uid: int = Depends(user_from_token)):
    with closing(db()) as c:
        rows = c.execute("SELECT action,ts,ip FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 100", (uid,)).fetchall()
    return [dict(r) for r in rows]


@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; "
        "frame-src blob:; object-src blob:; connect-src 'self'"
    )
    return resp


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", 8000)))
