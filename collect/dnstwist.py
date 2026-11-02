"""Домены-двойники через dnstwist.

Добавляется слой от методологии: dnstwist отвечает на вопрос «какие похожие
домены существуют», а предикаты отвечают на вопрос «какой из них является
признаком».

Требуется установленный dnstwist:  pip install dnstwist
"""
import json, subprocess, shutil, sys
try:
    from ._common import Log, save
except ImportError:
    from _common import Log, save

# Подмена алфавита включена сознательно: для русскоязычного сегмента
# визуально совпадающие буквы — рабочий приём.
FUZZERS = "addition,bitsquatting,homoglyph,hyphenation,insertion,omission," \
          "repetition,replacement,subdomain,transposition,vowel-swap"

# Обезвреженный двойник: почта никуда не идёт — защитная регистрация, то есть
# признак, обратный готовности к рассылке. Нулевая MX задана RFC 7505.
NEUTRALIZED_MX = ("blackhole", "void.", "sinkhole", "null.", "localhost",
                  "invalid.", "example.com", "does-not-exist")

def mx_neutralized(mx_records):
    """Возвращает (признак_обезврежен, причина). Нулевая MX по RFC 7505 и
    известные чёрные дыры трактуются как отсутствие почтового канала."""
    if not mx_records:
        return True, "записи MX нет"
    for rec in mx_records:
        # Порядок важен: при обратном нулевая MX «0 .» разбирается неверно.
        parts = str(rec).strip().split()
        host = (parts[-1] if parts else "").rstrip(".").lower()
        if host in ("", "."):
            return True, "нулевая MX по RFC 7505: домен объявил, что почту не принимает"
        for marker in NEUTRALIZED_MX:
            if marker in host:
                return True, f"MX указывает на чёрную дыру ({host}): защитная регистрация"
    return False, ""

def available():
    """Проверка наличия инструмента. Отсутствие зависимости — это not_checked,
    а не отсутствие двойников."""
    return shutil.which("dnstwist") is not None

def run_dnstwist(domain, log, timeout=600):
    """Запуск dnstwist с выдачей в JSON. Только регистрации и записи DNS:
    баннеры, скриншоты и геолокация не запрашиваются — это обращения
    к инфраструктуре двойника, то есть активные методы."""
    cmd = ["dnstwist", "--registered", "--format", "json",
           "--fuzzers", FUZZERS, domain]
    log.step("запуск: " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        log.fail("dnstwist не установлен: pip install dnstwist"); return None
    except subprocess.TimeoutExpired:
        log.fail(f"dnstwist не завершился за {timeout} с"); return None
    if r.returncode != 0:
        log.fail(f"dnstwist вернул код {r.returncode}: {r.stderr[:200]}"); return None
    try:
        return json.loads(r.stdout or "[]")
    except json.JSONDecodeError as e:
        log.fail(f"разбор выдачи не удался: {e}. Первые 200 символов: {r.stdout[:200]}")
        return None

def _field(row, *names):
    """Имена полей менялись между версиями dnstwist (domain / domain-name),
    поэтому читаем по нескольким вариантам, а не по одному."""
    for n in names:
        if n in row: return row[n]
    return None

def collect(domain, obj=None, day=None, timeout=600):
    log = Log(); obj = obj or domain
    base = domain.split(".", 1)[0]
    d = {"domain": domain, "found": False, "tool": "dnstwist", "fuzzers": FUZZERS}

    if not available():
        log.fail("dnstwist недоступен — шаг НЕ ПРОВЕРЕН, а не «двойников нет»")
        d["status"] = "not_checked"
        d["reason"] = "dnstwist не установлен"
        save("dnstwist", obj, d, log, day); return d

    rows = run_dnstwist(domain, log, timeout)
    if rows is None:
        d["status"] = "not_checked"; d["reason"] = "dnstwist завершился с ошибкой"
        save("dnstwist", obj, d, log, day); return d

    registered = []
    for row in rows:
        name = _field(row, "domain", "domain-name")
        if not name or name == domain: continue
        a  = _field(row, "dns_a", "dns-a") or []
        mx = _field(row, "dns_mx", "dns-mx") or []
        ns = _field(row, "dns_ns", "dns-ns") or []
        registered.append({
            "domain": name,
            "fuzzer": _field(row, "fuzzer") or "",
            "a": a, "mx": mx, "ns": ns,
            "idna": name.encode("idna").decode() if not name.isascii() else None,
            "mail_ready": bool(mx),
        })

    # Уровни: 0 — обезврежен (защитная регистрация), 1 — почта принимается,
    # принадлежность не установлена (развилка), 2 — принадлежность подтверждена
    # аналитиком в data/manual.json. В расчёт входит только уровень 2;
    # автоматического перехода 1 -> 2 нет.
    neutralized, candidates = [], []
    for x in registered:
        dead, why = mx_neutralized(x["mx"])
        if dead:
            x["level"] = 0; x["excluded_reason"] = why
            x["note"] = f"в расчёт не входит: {why}"
            neutralized.append(x)
        else:
            x["level"] = 1
            x["note"] = ("почта принимается, но принадлежность объекту "
                         "не установлена: развилка, требующая проверки")
            candidates.append(x)
    mail_ready = candidates

    d["registered"] = registered
    d["registered_count"] = len(registered)
    d["neutralized_count"] = len(neutralized)
    d["candidates_count"] = len(candidates)
    d["mail_ready_count"] = len(candidates)        # совместимость с прежним полем
    d["non_ascii_count"] = sum(1 for x in registered if x["idna"])
    # До подтверждения принадлежности — «проверено, не обнаружено».
    d["found"] = False
    d["status"] = "not_found"
    d["in_calculation"] = 0
    d["forks"] = [{"domain": x["domain"], "fuzzer": x["fuzzer"], "mx": x["mx"],
                   "question": "принадлежит ли домен организации, не связанной с объектом"}
                  for x in candidates]

    # Диагностика, не предикат: порога нет, обоснованного значения для него
    # источников не найдено.
    d["distinctiveness"] = {
        "base_name": base, "length": len(base),
        "registered_share": (len(registered) / len(rows)) if rows else None,
        "note": ("Доля зарегистрированных вариантов — показатель информативности "
                 "признака, а не порог отбора. Высокая доля у короткого имени "
                 "означает, что варианты совпадают с существующими словами, и "
                 "каждый найденный двойник требует отдельной проверки "
                 "принадлежности: домен может принадлежать не связанной "
                 "с объектом организации."),
    }
    log.ok(f"зарегистрировано {len(registered)}; обезврежено {len(neutralized)}; "
           f"кандидатов {len(candidates)}; с подменой алфавита {d['non_ascii_count']}")
    for x in neutralized[:5]:
        log.ok(f"  обезврежен: {x['domain']} — {x['excluded_reason']}")
    for x in candidates[:10]:
        log.warn(f"  РАЗВИЛКА: {x['domain']} ({x['fuzzer']}), MX {x['mx']}")
    log.ok("В РАСЧЁТ ВХОДИТ 0 признаков: наличие MX у похожего домена — наблюдение "
           "о домене, а не о нацеливании на объект")
    log.warn("уровень 2 присваивается только после ручной проверки принадлежности, "
             "записанной в data/manual.json")
    save("dnstwist", obj, d, log, day)
    return d

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True); ap.add_argument("--object")
    ap.add_argument("--timeout", type=int, default=600)
    a = ap.parse_args(); collect(a.domain, a.object, timeout=a.timeout)
