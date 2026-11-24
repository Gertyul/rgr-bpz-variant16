# РГР з дисципліни «Безпека програмного забезпечення» - варіант 16

Наскрізний аудит захищеності навчального застосунку **DVWA** (PHP).
Профіль варіанта 16 - **CSRF та керування сесіями**.

> ⚠️ Стенд навмисно вразливий. Розгортати й досліджувати лише в ізольованому
> середовищі на `127.0.0.1`. Застосування засобів аудиту до сторонніх систем
> заборонено (ст. 361–363-1 ККУ).

## Структура

```
dvwa/                      вихідний код цілі (DVWA) з внесеними виправленнями
docker-compose.yml         ізольований стенд: dvwa (127.0.0.1:4280) + MariaDB (internal)
.env.example               шаблон параметрів (скопіювати у .env)
tests/
  dvwa_client.py           клієнт стенда
  test_regression.py       9 регресійних тестів (pytest)
exploits/
  run_exploits.py          відтворення V1–V6 (before|after)
  screenshots.py           знімки екрана доказів
  triage.py                тріаж знахідок інструментів
poc/csrf.html              сторінка «зловмисника» для демонстрації CSRF
security/rules/            власне правило Semgrep
scan/{before,after}/       звіти SAST/SCA/секретів і тріаж
evidence/{before,after}/   докази експлуатації (запити/відповіді, знімки)
report/                    звіт (.docx, .pdf)
.github/workflows/         конвеєр CI: SAST, SCA, секрети, регресія
```

## Запуск

```bash
cp .env.example .env            # задати власні синтетичні паролі й DVWA_COOKIE_SECRET
docker compose up -d --build    # стенд на http://127.0.0.1:4280 (admin/password)
# ініціалізація БД: відкрити /setup.php → Create/Reset Database
pip install pytest requests playwright
pytest tests/test_regression.py -v
```

Відтворення вразливостей і повторний прогін:

```bash
python exploits/run_exploits.py before
python exploits/run_exploits.py after
```

## Результат

| ID | Вразливість | CWE | CVSS | До | Після |
|----|-------------|-----|------|----|-------|
| V1 | CSRF зміни пароля | CWE-352 | 8.1 | EXPLOITED | BLOCKED |
| V2 | Фіксація сесії | CWE-384 | 6.8 | EXPLOITED | BLOCKED |
| V3 | Передбачувані session ID | CWE-330 | 9.1 | EXPLOITED | BLOCKED |
| V4 | Cookie без HttpOnly/SameSite | CWE-1004 | 7.1 | EXPLOITED | BLOCKED |
| V5 | Підміна cookie рівня безпеки | CWE-602 | 8.1 | EXPLOITED | BLOCKED |
| V6 | Передбачуваний CSRF-токен | CWE-330 | 6.8 | EXPLOITED | BLOCKED |

Усі 9 регресійних тестів проходять; власне правило Semgrep після виправлення - 0 знахідок.
Звіт: `report/RGR_variant16_DVWA.pdf`.
