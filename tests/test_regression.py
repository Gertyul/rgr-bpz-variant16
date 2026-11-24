"""Регресійні тести РГР (варіант 16: CSRF та керування сесіями).

Кожен тест відтворює вразливість і стверджує, що після виправлення її УСУНЕНО.
Тести виконуються проти локального стенда 127.0.0.1 і не дозволяють дефектам
повернутися. Запуск:  pytest -v   (з каталогу RGR_v16_DVWA).
"""
import os
import re
import sys

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import dvwa_client as dc


@pytest.fixture(scope="session", autouse=True)
def _ready():
    dc.wait_ready()
    dc.setup_db()
    dc.reset_admin_password()
    yield
    dc.reset_admin_password()


@pytest.fixture
def admin():
    s = dc.admin_low()
    assert dc.is_logged_in(s), "не вдалося увійти як admin"
    return s


# --- V1. CSRF: зміна пароля вимагає анти-CSRF токена ------------------------
def test_v1_csrf_without_token_blocked(admin):
    dc.reset_admin_password()
    url = dc.BASE + "/vulnerabilities/csrf/?password_new=attack1&password_conf=attack1&Change=Change"
    r = admin.get(url, headers={"Referer": "http://localhost:8081/"})
    assert "Password Changed." not in r.text
    assert not dc.can_login("attack1"), "пароль змінено без токена — CSRF не усунено"


def test_v1_csrf_with_valid_token_allowed(admin):
    """Легітимна зміна пароля через інтерфейс (з токеном) має працювати."""
    dc.reset_admin_password()
    page = admin.get(dc.BASE + "/vulnerabilities/csrf/")
    token = dc.get_token(page.text)
    assert token, "сторінка не містить анти-CSRF токена"
    r = admin.get(dc.BASE + "/vulnerabilities/csrf/", params={
        "password_new": "newpass1", "password_conf": "newpass1",
        "Change": "Change", "user_token": token})
    assert "Password Changed." in r.text
    assert dc.can_login("newpass1")
    dc.reset_admin_password()


# --- V2. Фіксація сесії: ідентифікатор регенерується після входу ------------
def test_v2_session_id_regenerated_on_login():
    s = requests.Session()
    s.get(dc.BASE + "/login.php")
    pre = [c.value for c in s.cookies if c.name == "PHPSESSID"][-1]
    r = s.get(dc.BASE + "/login.php")
    s.post(dc.BASE + "/login.php",
           data={"username": "admin", "password": "password", "Login": "Login",
                 "user_token": dc.get_token(r.text)})
    post = [c.value for c in s.cookies if c.name == "PHPSESSID"][-1]
    assert pre != post, "PHPSESSID не змінився після входу — можлива фіксація сесії"
    # Початковий (доавтентифікаційний) ідентифікатор не дає доступу.
    hij = requests.Session()
    hij.cookies.set("PHPSESSID", pre, domain="127.0.0.1")
    assert not dc.is_logged_in(hij)


# --- V3. Слабкі ідентифікатори сесії: значення непередбачувані ---------------
@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_v3_weak_session_id_unpredictable(level):
    s = dc.login()
    dc.set_level(s, level)
    vals = []
    for _ in range(5):
        r = s.post(dc.BASE + "/vulnerabilities/weak_id/", data={})
        v = r.cookies.get("dvwaSession")
        if v:
            vals.append(v)
    assert len(vals) >= 2
    assert len(set(vals)) == len(vals), "значення повторюються"
    # Не мають бути послідовними цілими.
    try:
        ints = [int(v) for v in vals]
        assert not all(b - a == 1 for a, b in zip(ints, ints[1:]))
    except ValueError:
        pass  # не числа — тим паче непередбачувані
    # Достатня довжина (ентропія).
    assert all(len(v) >= 24 for v in vals)


# --- V4. Прапорці cookie: HttpOnly та SameSite присутні ----------------------
def test_v4_session_cookie_has_security_flags():
    s = requests.Session()
    r = s.get(dc.BASE + "/login.php")
    r = s.post(dc.BASE + "/login.php",
               data={"username": "admin", "password": "password", "Login": "Login",
                     "user_token": dc.get_token(r.text)}, allow_redirects=False)
    sc = r.headers.get("Set-Cookie", "")
    assert re.search(r"PHPSESSID=", sc)
    assert "httponly" in sc.lower(), "немає прапорця HttpOnly"
    assert "samesite" in sc.lower(), "немає прапорця SameSite"


# --- V5. Цілісність cookie 'security': підробка відхиляється -----------------
def test_v5_tampered_security_cookie_rejected():
    s = dc.login()
    dc.set_level(s, "impossible")
    # Клієнт підмінює cookie на непідписане 'low'.
    for c in list(s.cookies):
        if c.name == "security":
            s.cookies.clear(c.domain, c.path, c.name)
    s.cookies.set("security", "low", domain="127.0.0.1", path="/")
    r = s.get(dc.BASE + "/security.php")
    assert "<em>low</em>" not in r.text, "підроблену cookie прийнято — рівень знижено"
    assert "<em>impossible</em>" in r.text


# --- V6. Анти-CSRF токен: криптографічно стійкий ----------------------------
def test_v6_csrf_token_strength():
    tokens = set()
    for _ in range(10):
        s = requests.Session()
        tokens.add(dc.get_token(s.get(dc.BASE + "/login.php").text))
    assert len(tokens) == 10, "токени повторюються"
    for t in tokens:
        assert len(t) >= 32 and re.fullmatch(r"[0-9a-f]+", t), f"слабкий токен: {t}"
