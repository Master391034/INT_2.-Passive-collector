"""Пассивный фингерпринт главной страницы. Ровно один запрос.

Обход сайта, перебор путей, запрос служебных файлов и проверка уязвимостей
не выполняются: всё перечисленное является активной разведкой."""
import urllib.request, re
try:
    from ._common import Log, save          # как часть пакета collect
except ImportError:
    from _common import Log, save          # при запуске файлом напрямую

# Поставщики медицинских информационных систем: домен -> описание.
# Список расширяется по наблюдениям, а не угадывается.
VENDORS = {
    "infoclinica.ru": "медицинская информационная система Инфоклиника",
    "medesk.net":     "медицинская информационная система Medesk",
    "renovatio.pro":  "медицинская информационная система Renovatio",
    "klinikaonline":  "медицинская информационная система",
    "1c-bitrix":      "платформа сайта 1С-Битрикс",
    "bitrix24":       "корпоративный портал Битрикс24",
    "b24u.ru":        "интеграция Битрикс24",
    "comagic.ru":     "коллтрекинг Comagic",
}
PLATFORMS = {
    "1С-Битрикс": ["bitrix/js", "bx-", "BX.ready"],
    "WordPress":  ["wp-content", "wp-includes"],
    "jQuery":     ["jquery"],
    "Яндекс Метрика": ["mc.yandex.ru", "ym("],
    "Google Analytics": ["google-analytics", "gtag(", "googletagmanager"],
}

# Заголовки обычного браузера.
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
    "Accept-Encoding": "identity",     # без сжатия: разбор идёт по тексту
    "Connection": "close",
}

def collect(domain, obj=None, day=None, timeout=60, attempts=2):
    log = Log(); obj = obj or domain
    url = f"https://{domain}"
    log.step("один запрос главной страницы; обход сайта не выполняется")
    log.url(url)
    d = {"url": url, "found": False}
    html = hdr = None
    last = None
    for n in range(1, attempts + 1):
        # Повтор только при сетевом отказе и только один раз: это тот же
        # единственный запрос, а не обход.
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            r = urllib.request.urlopen(req, timeout=timeout)
            html = r.read(1_500_000).decode("utf-8", "replace")
            hdr = {k.lower(): v for k, v in r.headers.items()}
            if n > 1: log.ok(f"получено со попытки {n}")
            break
        except Exception as e:
            last = e
            log.warn(f"попытка {n} из {attempts}: {type(e).__name__}: {e}")
    if html is None:
        log.fail(f"страница недоступна после {attempts} попыток: "
                 f"{type(last).__name__}: {last}")
        d["status"] = "not_checked"
        d["reason"] = f"{type(last).__name__}: {last}"
        save("fingerprint", obj, d, log, day); return d
    d["found"] = True
    d["headers"] = {"server": hdr.get("server"),
                    "missing_security_headers": [h for h in
                        ("content-security-policy","x-frame-options","x-content-type-options")
                        if h not in hdr]}
    d["markup"] = {p: [m for m in marks if m.lower() in html.lower()]
                   for p, marks in PLATFORMS.items()}
    d["markup"] = {k: v for k, v in d["markup"].items() if v}
    # внешние хосты из разметки
    hosts = {}
    for m in re.finditer(r'https?://([a-z0-9\.\-]+)', html, re.I):
        h = m.group(1).lower()
        if h.endswith(domain): continue
        hosts[h] = hosts.get(h, 0) + 1
    d["external_hosts"] = dict(sorted(hosts.items(), key=lambda x: -x[1]))
    # зависимости: уровень определяется именованием поддомена по объекту
    base = domain.split(".")[0]
    vendors = []
    for h, cnt in hosts.items():
        for vd, desc in VENDORS.items():
            if vd in h:
                named = base in h or any(p and p in h for p in (base[:6],))
                vendors.append({"host": h, "description": desc, "reference_count": cnt,
                                "named_after_object": named,
                                "level": 2 if named else 1,
                                "note": ("поддомен назван по объекту на домене поставщика: "
                                         "условие уровня 2 выполнено прямым наблюдением")
                                        if named else
                                        ("домен поставщика присутствует, но поддомен по объекту "
                                         "не назван: уровень 1, основание для проверки, "
                                         "в значение группы не входит")})
    d["vendors"] = vendors
    d["method_note"] = ("Выполнен один запрос главной страницы. Перебор путей, обход сайта, "
                        "запрос служебных файлов и проверка уязвимостей не выполнялись.")
    d["limitation_note"] = ("Признак относится к публичному сайту, а не к системам обработки "
                            "данных; различить их пассивно нельзя. Признаки платформы удаляются "
                            "настройкой, поэтому их отсутствие ничего не доказывает.")
    log.ok(f"внешних хостов: {len(hosts)}, поставщиков распознано: {len(vendors)}")
    for v in vendors: log.ok(f"  {v['host']} -> уровень {v['level']}")
    save("fingerprint", obj, d, log, day)
    return d

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("--domain", required=True)
    ap.add_argument("--object"); ap.add_argument("--timeout", type=int, default=60)
    a = ap.parse_args()
    collect(a.domain, a.object, timeout=a.timeout)
