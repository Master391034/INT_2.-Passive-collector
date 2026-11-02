"""DNS через публичные разрешители.

Используется dig, потому что он есть в macOS и Linux из коробки: внешних
библиотек не требуется. Два независимых разрешителя — требование шкалы
достоверности: одиночный ответ достоверность 1 не получает."""
import subprocess, sys, re
try:
    from ._common import Log, save          # как часть пакета collect
except ImportError:
    from _common import Log, save          # при запуске файлом напрямую

RESOLVERS = ["8.8.8.8", "1.1.1.1"]

def dig(name, rtype, resolver):
    """Один запрос. Возвращает список строк ответа либо None при отказе.
    None и пустой список — разные вещи: None значит «не спросили»,
    пустой список значит «спросили, записи нет»."""
    try:
        r = subprocess.run(["dig", f"@{resolver}", "+short", "+time=4", "+tries=1", rtype, name],
                           capture_output=True, text=True, timeout=12)
        if r.returncode != 0: return None
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return None

def both(name, rtype, log):
    """Ответ принимается, когда совпал у двух разрешителей. Расхождение
    фиксируется предупреждением: это либо балансировка, либо подмена."""
    a, b = dig(name, rtype, RESOLVERS[0]), dig(name, rtype, RESOLVERS[1])
    if a is None and b is None:
        log.fail(f"{rtype} {name}: оба разрешителя не ответили")
        return None, "not_checked"
    if a is None or b is None:
        log.warn(f"{rtype} {name}: ответил один разрешитель из двух, достоверность снижена")
        return (a or b), "single"
    if set(a) != set(b):
        log.warn(f"{rtype} {name}: разрешители разошлись: {a} против {b}")
        return sorted(set(a) | set(b)), "diverged"
    return a, "both"

def collect(domain, hosts=None, obj=None, day=None):
    log = Log(); obj = obj or domain
    log.step(f"DNS по {domain}, разрешители {', '.join(RESOLVERS)}")
    d = {"domain": domain, "found": False, "resolvers": RESOLVERS}

    for rtype, key in (("A","a"), ("MX","mx"), ("NS","ns"), ("TXT","txt")):
        v, how = both(domain, rtype, log)
        d[key] = v; d[key + "_quality"] = how
        if v: log.ok(f"{rtype}: {len(v)} записей")
    d["found"] = bool(d.get("a"))

    # Политика важнее наличия. Качество ответа доходит до признака: отказ
    # разрешителя не должен превращаться в «записи нет».
    txt_checked = d.get("txt_quality") != "not_checked"
    spf = next((t for t in (d.get("txt") or []) if "v=spf1" in t), None)
    if not txt_checked:
        d["spf"] = {"present": None, "status": "not_checked",
                    "reason": "TXT не получен: разрешители не ответили"}
        log.fail("SPF: НЕ ПРОВЕРЕН — TXT не получен")
    elif spf:
        pol = re.search(r"([~\-+?])all", spf)
        d["spf"] = {"present": True, "record": spf.strip('"'),
                    "policy": (pol.group(0) if pol else "не указана"),
                    "meaning": {"~all":"мягкий отказ, письмо помечается, но доставляется",
                                "-all":"жёсткий отказ",
                                "+all":"разрешено всем, защиты нет",
                                "?all":"нейтрально, защиты нет"}.get(pol.group(0) if pol else "", "")}
        d["spf"]["status"] = "confirmed"
        log.ok(f"SPF: политика {d['spf']['policy']}")
    else:
        d["spf"] = {"present": False, "status": "not_found"}
        log.ok("SPF: запись отсутствует — источник проверен, результат отрицательный")

    v, how = both("_dmarc." + domain, "TXT", log)
    if how == "not_checked":
        d["dmarc"] = {"present": None, "status": "not_checked",
                      "reason": "разрешители не ответили"}
        log.fail("DMARC: НЕ ПРОВЕРЕН — отсутствие записи не установлено")
    else:
        has = bool(v and any("v=DMARC1" in x for x in v))
        d["dmarc"] = {"present": has, "record": (v[0].strip('"') if has else None),
                      "status": "confirmed" if has else "not_found", "quality": how}
        log.ok(f"DMARC: {'есть' if has else 'отсутствует — источник проверен'}")

    # Разрешимость имён из журнала сертификатов. Предикат: имя без записи A
    # признаком не является — сертификат мог выпускаться когда угодно.
    if hosts:
        log.step(f"проверка разрешимости {len(hosts)} имён из журнала сертификатов")
        res, addrs = {}, {}
        for h in hosts:
            a = dig(h, "A", RESOLVERS[0])
            ips = [x for x in (a or []) if re.fullmatch(r"[\d.]+", x)]
            res[h] = ips
            for ip in ips: addrs.setdefault(ip, []).append(h)
        d["hosts_checked"] = res
        d["addresses"] = addrs
        d["resolved_count"] = sum(1 for v2 in res.values() if v2)
        log.ok(f"разрешилось {d['resolved_count']} из {len(hosts)}; "
               f"уникальных адресов {len(addrs)}")
        log.ok("ДЕДУПЛИКАЦИЯ: имена, указывающие на общий адрес, — один узел")
    save("dns", obj, d, log, day)
    return d

if __name__ == "__main__":
    import argparse, json as J
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--hosts-from-crtsh", action="store_true",
                    help="взять имена из снимка crtsh того же дня")
    ap.add_argument("--object")
    a = ap.parse_args()
    hosts = None
    if a.hosts_from_crtsh:
        # Самый свежий снимок, в котором отработал именно crt.sh.
        from paths import latest_for
        obj = a.object or a.domain
        cday, cpath = latest_for(obj, "crtsh")
        if cpath is None:
            print("! снимка crt.sh нет ни за одну дату: имена не подставляются")
        else:
            hosts = J.load(open(cpath))["data"]["hosts"]
            print(f"имена из снимка crt.sh за {cday}: {len(hosts)}")
    collect(a.domain, hosts, a.object)
