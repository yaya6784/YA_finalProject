from __future__ import annotations

__author__ = "Eilay Zafira"

import os
import pickle
import secrets
import tempfile
import threading
import time
import hmac
import hashlib

DB_FILE = os.path.join(os.path.dirname(__file__), "users.pkl")
_lock = threading.Lock()
_users = {}


def init_db(db_file: str = DB_FILE) -> None:
    global _users, DB_FILE
    DB_FILE = db_file
    _users = _load_users(DB_FILE)


def _load_users(path: str):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "rb") as f:
            data = pickle.load(f)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def _save_users(path: str, users) -> None:
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix="users_", suffix=".pkl", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            pickle.dump(users, f)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _now() -> float:
    return time.time()


def cleanup_expired() -> None:
    with _lock:
        changed = False
        t = _now()
        to_delete = []
        for u, rec in _users.items():
            if rec.get("status") == "pending":
                exp = rec.get("signup_expires")
                if exp is not None and exp < t:
                    to_delete.append(u)
        for u in to_delete:
            del _users[u]
            changed = True
        for rec in _users.values():
            exp = rec.get("reset_expires")
            if exp is not None and exp < t and rec.get("reset_code") is not None:
                rec["reset_code"] = None
                rec["reset_expires"] = None
                changed = True
            texp = rec.get("reset_token_expires")
            if texp is not None and texp < t and rec.get("reset_token") is not None:
                rec["reset_token"] = None
                rec["reset_token_expires"] = None
                changed = True
        if changed:
            _save_users(DB_FILE, _users)


def is_user_exist(username: str) -> bool:
    cleanup_expired()
    with _lock:
        return username in _users


def is_user_active(username: str) -> bool:
    cleanup_expired()
    with _lock:
        return username in _users and _users[username].get("status") == "active"


def get_user(username: str):
    cleanup_expired()
    with _lock:
        rec = _users.get(username)
        return dict(rec) if isinstance(rec, dict) else None


def compute_hash_sha256(password_plain: str, salt_hex: str, pepper: str) -> str:
    msg = (password_plain + salt_hex + pepper).encode("utf-8", errors="ignore")
    return hashlib.sha256(msg).hexdigest()


def signup_start(username: str, password_plain: str, email: str, pepper: str, ttl_seconds: int = 300):
    cleanup_expired()
    username = (username or "").strip()
    email_norm = (email or "").strip().lower()
    if not username or not password_plain or not email_norm:
        return False, "MISSING_FIELDS"
    with _lock:
        if username in _users:
            return False, "USERNAME_TAKEN"
        for rec in _users.values():
            if (rec.get("email") or "").strip().lower() == email_norm:
                return False, "EMAIL_TAKEN"
        salt = secrets.token_hex(16)
        pass_hash = compute_hash_sha256(password_plain, salt, pepper)
        code = f"{secrets.randbelow(10**6):06d}"
        exp = _now() + int(ttl_seconds)
        _users[username] = {
            "email": email_norm,
            "salt": salt,
            "pass_hash": pass_hash,
            "status": "pending",
            "signup_code": code,
            "signup_expires": exp,
            "reset_code": None,
            "reset_expires": None,
            "reset_token": None,
            "reset_token_expires": None,
        }
        _save_users(DB_FILE, _users)
    return True, code


def signup_resend(email: str, pepper: str, ttl_seconds: int = 300):
    cleanup_expired()
    email_norm = (email or "").strip().lower()
    if not email_norm:
        return False, "MISSING_FIELDS", None
    with _lock:
        target_user = None
        for u, rec in _users.items():
            if (rec.get("email") or "").strip().lower() == email_norm and rec.get("status") == "pending":
                target_user = u
                break
        if not target_user:
            return False, "NO_PENDING_SIGNUP", None
        code = f"{secrets.randbelow(10**6):06d}"
        _users[target_user]["signup_code"] = code
        _users[target_user]["signup_expires"] = _now() + int(ttl_seconds)
        _save_users(DB_FILE, _users)
    return True, "CODE_RESENT", code


def signup_verify(email: str, code: str):
    cleanup_expired()
    email_norm = (email or "").strip().lower()
    code = (code or "").strip()
    if not email_norm or not code:
        return False, "MISSING_FIELDS", None
    with _lock:
        target_user = None
        rec = None
        for u, r in _users.items():
            if (r.get("email") or "").strip().lower() == email_norm and r.get("status") == "pending":
                target_user = u
                rec = r
                break
        if not target_user or rec is None:
            return False, "NO_PENDING_SIGNUP", None
        exp = rec.get("signup_expires")
        if exp is None or exp < _now():
            del _users[target_user]
            _save_users(DB_FILE, _users)
            return False, "CODE_EXPIRED", None
        if (rec.get("signup_code") or "") != code:
            return False, "CODE_INVALID", None
        rec["status"] = "active"
        rec["signup_code"] = None
        rec["signup_expires"] = None
        _save_users(DB_FILE, _users)
    return True, "SIGNUP_DONE", target_user


def is_password_ok(username: str, password_plain: str, pepper: str) -> bool:
    cleanup_expired()
    with _lock:
        rec = _users.get(username)
        if not rec or rec.get("status") != "active":
            return False
        salt = rec.get("salt") or ""
        stored = rec.get("pass_hash") or ""
    computed = compute_hash_sha256(password_plain, salt, pepper)
    return hmac.compare_digest(stored, computed)


def forgot_start(email: str, ttl_seconds: int = 300):
    cleanup_expired()
    email_norm = (email or "").strip().lower()
    if not email_norm:
        return False, "MISSING_FIELDS", None
    with _lock:
        target_user = None
        for u, rec in _users.items():
            if (rec.get("email") or "").strip().lower() == email_norm and rec.get("status") == "active":
                target_user = u
                break
        if not target_user:
            return True, "IF_EXISTS_CODE_SENT", None
        code = f"{secrets.randbelow(10**6):06d}"
        _users[target_user]["reset_code"] = code
        _users[target_user]["reset_expires"] = _now() + int(ttl_seconds)
        _save_users(DB_FILE, _users)
        return True, "CODE_SENT", code


def forgot_resend(email: str, ttl_seconds: int = 300):
    return forgot_start(email, ttl_seconds=ttl_seconds)


def forgot_verify(email: str, code: str, token_ttl_seconds: int = 600):
    cleanup_expired()
    email_norm = (email or "").strip().lower()
    code = (code or "").strip()
    if not email_norm or not code:
        return False, "MISSING_FIELDS", None
    with _lock:
        target_user = None
        rec = None
        for u, r in _users.items():
            if (r.get("email") or "").strip().lower() == email_norm and r.get("status") == "active":
                target_user = u
                rec = r
                break
        if not target_user or rec is None:
            return False, "CODE_INVALID", None
        exp = rec.get("reset_expires")
        if exp is None:
            return False, "CODE_INVALID", None
        if exp < _now():
            rec["reset_code"] = None
            rec["reset_expires"] = None
            _save_users(DB_FILE, _users)
            return False, "CODE_EXPIRED", None
        if (rec.get("reset_code") or "") != code:
            return False, "CODE_INVALID", None
        token = secrets.token_urlsafe(16)
        rec["reset_token"] = token
        rec["reset_token_expires"] = _now() + int(token_ttl_seconds)
        rec["reset_code"] = None
        rec["reset_expires"] = None
        _save_users(DB_FILE, _users)
        return True, "TOKEN_OK", token


def reset_password(email: str, token: str, new_password_plain: str, pepper: str):
    cleanup_expired()
    email_norm = (email or "").strip().lower()
    token = (token or "").strip()
    if not email_norm or not token or not new_password_plain:
        return False, "MISSING_FIELDS"
    with _lock:
        target_user = None
        rec = None
        for u, r in _users.items():
            if (r.get("email") or "").strip().lower() == email_norm and r.get("status") == "active":
                target_user = u
                rec = r
                break
        if not target_user or rec is None:
            return False, "TOKEN_INVALID"
        texp = rec.get("reset_token_expires")
        if texp is None or texp < _now():
            rec["reset_token"] = None
            rec["reset_token_expires"] = None
            _save_users(DB_FILE, _users)
            return False, "TOKEN_EXPIRED"
        if (rec.get("reset_token") or "") != token:
            return False, "TOKEN_INVALID"
        salt = secrets.token_hex(16)
        rec["salt"] = salt
        rec["pass_hash"] = compute_hash_sha256(new_password_plain, salt, pepper)
        rec["reset_token"] = None
        rec["reset_token_expires"] = None
        _save_users(DB_FILE, _users)
    return True, "RESET_DONE"


def get_user_email(username: str) -> str:
    cleanup_expired()
    with _lock:
        if username in _users:
            return _users[username].get("email", "")
        return ""
