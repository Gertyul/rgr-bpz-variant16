"""Допоміжний клієнт для стенда DVWA (лише 127.0.0.1)."""
import os
import re
import time

import requests

BASE = os.environ.get("DVWA_URL", "http://127.0.0.1:4280")
assert re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?$", BASE), "Дозволено лише локальний стенд"

ADMIN_USER = "admin"
ADMIN_PASS = "password"  # синтетичний обліковий запис DVWA за замовчуванням

TOKEN_RE = re.compile(r"name=['\"]user_token['\"] value=['\"]([^'\"]+)['\"]")


def get_token(html: str) -> str:
    m = TOKEN_RE.search(html)
    return m.group(1) if m else ""


def wait_ready(timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if requests.get(BASE + "/login.php", timeout=3).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError("DVWA не відповідає")


def setup_db():
    """Створює/скидає БД DVWA через setup.php."""
    s = requests.Session()
    r = s.get(BASE + "/setup.php")
    s.post(BASE + "/setup.php", data={"create_db": "Create / Reset Database",
                                      "user_token": get_token(r.text)})
    return s


def login(user=ADMIN_USER, password=ADMIN_PASS, session=None):
    s = session or requests.Session()
    r = s.get(BASE + "/login.php")
    s.post(BASE + "/login.php", data={"username": user, "password": password,
                                      "Login": "Login", "user_token": get_token(r.text)},
           allow_redirects=True)
    return s


def is_logged_in(s) -> bool:
    r = s.get(BASE + "/index.php", allow_redirects=False)
    return r.status_code == 200


def set_level(s, level="low"):
    r = s.get(BASE + "/security.php")
    s.post(BASE + "/security.php", data={"security": level, "seclev_submit": "Submit",
                                         "user_token": get_token(r.text)})
    return s


def admin_low():
    s = login()
    set_level(s, "low")
    return s


def can_login(password) -> bool:
    return is_logged_in(login(ADMIN_USER, password))


def reset_admin_password():
    """Повертає пароль admin до 'password' прямим запитом у БД контейнера (лише стенд)."""
    import subprocess
    env = {}
    with open(os.path.join(os.path.dirname(__file__), "..", ".env"), encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v
    subprocess.run(["docker", "compose", "exec", "-T", "db", "mariadb", "-udvwa",
                    "-p" + env["DVWA_DB_PASSWORD"], "dvwa", "-e",
                    "UPDATE users SET password=MD5('password') WHERE user='admin';"],
                   check=True, capture_output=True,
                   cwd=os.path.join(os.path.dirname(__file__), ".."))
