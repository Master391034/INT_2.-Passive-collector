"""Журналы прозрачности сертификатов через crt.sh.

Собственных признаков источник не даёт: имя в журнале означает, что на него
выпускали сертификат, а не что узел существует. Результат — список кандидатов
для проверки разрешимости в DNS."""
import json, urllib.request, urllib.parse, re
try:
    from ._common import Log, save          # как часть пакета collect
except ImportError:
    from _common import Log, save          # при запуске файлом напрямую

def collect(domain, obj=None, day=None):
    log = Log(); obj = obj or domain
    log.step(f"запрос журналов прозрачности по %.{domain}")
    url = f"https://crt.sh/?q={urllib.parse.quote('%.'+domain)}&output=json"
    log.url(url)
    d = {"domain": domain, "found": False, "hosts": [], "wildcards": [], "flagged": []}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "targetmap/1.0"})
        rows = json.load(urllib.request.urlopen(req, timeout=60))
    except Exception as e:
        log.fail(f"источник недоступен: {type(e).__name__}: {e}")
        save("crtsh", obj, d, log, day)       # снимок пишется и при отказе
        return d
    names, first_seen, issuers = set(), {}, {}
    for r in rows:
        for n in str(r.get("name_value", "")).splitlines():
            n = n.strip().lower()
            if not n or not n.endswith(domain): continue
            if n.startswith("*."):
                d["wildcards"].append(n); continue
            names.add(n)
            # дата первого появления: единственный признак источника, пригодный
            # для восстановления состояния на прошлую дату
            nb = r.get("not_before")
            if nb and (n not in first_seen or nb < first_seen[n]): first_seen[n] = nb
        i = r.get("issuer_name")
        if i: issuers[i] = issuers.get(i, 0) + 1
    d["hosts"] = sorted(names)
    d["host_count"] = len(names)
    d["first_seen"] = first_seen
    d["issuers"] = issuers
    d["wildcards"] = sorted(set(d["wildcards"]))
    # имена служебного вида — повод для проверки, но не признак сами по себе
    pat = re.compile(r"(dev|test|stage|staging|old|backup|vpn|mail|admin|api|crm|1c|bitrix)")
    d["flagged"] = [n for n in d["hosts"] if pat.search(n.split("."+domain)[0])]
    d["found"] = bool(names)
    log.ok(f"имён: {len(names)}, подстановочных: {len(d['wildcards'])}, "
           f"служебного вида: {len(d['flagged'])}")
    log.warn("собственного признака источник не даёт: это список кандидатов для DNS")
    save("crtsh", obj, d, log, day)
    return d

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("--domain", required=True)
    ap.add_argument("--object"); a = ap.parse_args()
    collect(a.domain, a.object)
