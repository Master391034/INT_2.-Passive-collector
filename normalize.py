"""Сырьё - записи наблюдений. Здесь живут предикаты применимости.

Модуль ничего не скачивает: читает снимки и решает, что из них является
признаком, а что остаётся основанием для проверки.
"""
import json, re
from features import RELIABILITY, CREDIBILITY
from paths import snapshot, latest_day, latest_for, sector_snapshot

# ---------------------------------------------------------------- Censys
def censys_services(host_record):
    """Службы из ответа Platform API. Структура ответа:
         {"result": {"resource": {..., "services": [...], "service_count": N}}}
    Отсутствие ключа services не означает отсутствия служб: бесплатный тариф
    отдаёт только базовые протоколы. Поэтому возвращается (службы, состояние),
    и при отсутствии данных состояние - not_checked, а не not_found."""
    res = (host_record or {}).get("result", {}).get("resource", {})
    svc = res.get("services")
    if svc is None:
        return [], "not_checked", "служб в ответе нет; бесплатный тариф отдаёт " \
                                  "только базовые протоколы, поэтому отсутствие " \
                                  "данных не равно отсутствию служб"
    out = []
    for s in svc:
        sw = []
        for x in (s.get("software") or []):
            if isinstance(x, dict):
                sw.append({"vendor": x.get("vendor"), "product": x.get("product"),
                           "version": x.get("version")})
        labels = [(l.get("value") if isinstance(l, dict) else str(l))
                  for l in (s.get("labels") or [])]
        out.append({"port": s.get("port"), "protocol": s.get("protocol"),
                    "transport": s.get("transport_protocol"),
                    "software": sw, "labels": labels,
                    "scan_time": s.get("scan_time"),
                    # Версия известна только если она явно указана в ПО.
                    # Иначе признак уязвимости не привязывается к активу.
                    "has_version": any(x.get("version") for x in sw)})
    return out, "confirmed", ""

def censys_names(host_record):
    res = (host_record or {}).get("result", {}).get("resource", {})
    d = res.get("dns") or {}
    names = list(d.get("names") or [])
    rev = ((d.get("reverse_dns") or {}).get("names") or [])
    return names, rev

def censys_asn(host_record):
    res = (host_record or {}).get("result", {}).get("resource", {})
    a = res.get("autonomous_system") or {}
    return a.get("description") or a.get("name") or ""

# Автоимена инфраструктуры: содержат сам адрес либо принадлежат службе
# подстановочного DNS. Не признак постороннего арендатора на адресе.
WILDCARD_DNS = ("sslip.io", "nip.io", "xip.io", "ispmanager.name", "in-addr.arpa",
                ".arpa", "amazonaws.com", "googleusercontent.com", "your-server.de",
                "cloudapp.azure.com", "vultrusercontent.com", "contaboserver.net")

def infra_name(name, ip):
    """Имя порождено инфраструктурой адреса, а не является именем арендатора."""
    n = name.lower()
    if any(w in n for w in WILDCARD_DNS):
        return True
    if ip and (ip in n or ip.replace(".", "-") in n):
        return True
    return False

# ------------------------------------------------- привязка адреса к объекту
def attribute(ip, own_names, host_record, object_domain, vendor_domains=()):
    """Кому принадлежит адрес. Возвращает (класс, причина).

    Признак открытой службы относится к объекту только если адрес ему
    принадлежит.
    Решение строится на двух источниках: собственные записи A говорят,
    какие имена объекта указывают на адрес, а список имён у оператора сканера
    показывает, кто ещё на этом адресе находится."""
    names, _ = censys_names(host_record)
    # Автоимена инфраструктуры отбрасываются до подсчёта: иначе одно имя
    # панели хостинга превращает свой адрес в чужой.
    names = [n for n in names if not infra_name(n, ip)]
    foreign = [n for n in names if not n.endswith(object_domain)]
    if not names:
        return "unknown", "у оператора сканера нет перечня имён для адреса"
    if not foreign:
        return "own", (f"все {len(names)} известных имён адреса принадлежат объекту "
                       f"(автоимена инфраструктуры исключены); признаков "
                       f"совместного размещения нет. Перечень имён у оператора "
                       f"ограничен сотней, поэтому это отсутствие свидетельств "
                       f"совместного размещения, а не доказательство выделенности")
    # Инфраструктура поставщика: чужие имена сосредоточены в одном домене,
    # который уже распознан как домен поставщика.
    for vd in vendor_domains:
        hit = [n for n in foreign if n.endswith(vd)]
        if hit and len(hit) >= max(1, len(foreign) // 2):
            return "supplier", (f"чужие имена принадлежат домену поставщика {vd} "
                                f"({len(hit)} из {len(foreign)}); адрес относится "
                                f"к инфраструктуре поставщика, не объекта")
    base = {}
    for n in foreign:
        base[".".join(n.split(".")[-2:])] = base.get(".".join(n.split(".")[-2:]), 0) + 1
    many = len(base) > 2
    return ("shared" if many else "foreign",
            f"на адресе {len(foreign)} имён, не принадлежащих объекту, "
            f"из {len(base)} сторонних доменов (например {sorted(base)[:3]}); "
            f"{'общий хостинг или узел защиты' if many else 'сторонняя инфраструктура'}: "
            f"службы объекту не принадлежат")

# ------------------------------------------------------- почтовый канал
def mail_channel(dns_data):
    """Признак подделки отправителя. Решает политика, а не наличие записи.

    DMARC с политикой none означает только наблюдение: отчёты собираются,
    но подделанное письмо доставляется. Поэтому наличие записи при p=none
    признак не снимает. То же со SPF: ~all доставляет письмо с пометкой."""
    out = []
    dm = dns_data.get("dmarc") or {}
    if dm.get("status") == "not_checked":
        out.append(dict(feature="REA.MAIL.DMARC", status="not_checked",
                        value_num=None, reliability=None, credibility=None,
                        predicate="not_applicable",
                        reason=dm.get("reason", "запись не получена")))
    else:
        rec = dm.get("record") or ""
        pol = (re.search(r"\bp\s*=\s*(none|quarantine|reject)", rec) or [None, None])[1] \
              if rec else None
        if not dm.get("present"):
            out.append(dict(feature="REA.MAIL.DMARC", status="confirmed", value_num=1.0,
                            reliability="A", credibility=1, predicate="passed",
                            note="записи DMARC нет: подделка отправителя не отклоняется"))
        elif pol == "reject":
            out.append(dict(feature="REA.MAIL.DMARC", status="not_found", value_num=0.0,
                            reliability="A", credibility=1, predicate="passed",
                            note="DMARC p=reject: подделка отправителя отклоняется, "
                                 "признака нет"))
        elif pol == "quarantine":
            out.append(dict(feature="REA.MAIL.DMARC", status="confirmed", value_num=0.5,
                            reliability="A", credibility=1, predicate="passed",
                            note="DMARC p=quarantine: письмо не отклоняется, "
                                 "а помещается в карантин — защита частичная"))
        else:
            out.append(dict(feature="REA.MAIL.DMARC", status="confirmed", value_num=1.0,
                            reliability="A", credibility=1, predicate="passed",
                            note=f"DMARC присутствует с политикой p={pol or 'none'}: "
                                 f"отчёты собираются, но подделанное письмо "
                                 f"доставляется — принуждения нет"))
    sp = dns_data.get("spf") or {}
    if sp.get("status") == "not_checked":
        out.append(dict(feature="REA.MAIL.SPF", status="not_checked", value_num=None,
                        reliability=None, credibility=None, predicate="not_applicable",
                        reason=sp.get("reason", "запись не получена")))
    else:
        pol = sp.get("policy")
        if not sp.get("present"):
            out.append(dict(feature="REA.MAIL.SPF", status="confirmed", value_num=1.0,
                            reliability="A", credibility=1, predicate="passed",
                            note="записи SPF нет"))
        elif pol == "-all":
            out.append(dict(feature="REA.MAIL.SPF", status="not_found", value_num=0.0,
                            reliability="A", credibility=1, predicate="passed",
                            note="SPF -all: жёсткий отказ, признака нет"))
        else:
            out.append(dict(feature="REA.MAIL.SPF", status="confirmed", value_num=1.0,
                            reliability="A", credibility=1, predicate="passed",
                            note=f"SPF {pol}: письмо доставляется, защита мягкая"))
    return out

# ------------------------------------------------- свёртка, вариант Б
def trust(rel, cred):
    return RELIABILITY.get(rel, 1.0) * CREDIBILITY.get(cred, 1.0)

def direction_value(weight, assets):
    """Значение направления: вес направления это потолок, а число подтверждённых
    активов приближает к нему с насыщением.

        p = вес × (1 − ∏(1 − доверие_актива)) """
    if not assets: return 0.0, 0.0
    prod = 1.0
    for a in assets:
        # value_num масштабирует вклад актива: DMARC с политикой quarantine
        # даёт 0.5, то есть половину вклада отсутствующей записи. Без этого
        # частичная защита считалась бы равной полному её отсутствию.
        v = a.get("value_num")
        v = 1.0 if v is None else float(v)
        prod *= (1.0 - v * trust(a.get("reliability"), a.get("credibility")))
    saturation = 1.0 - prod
    return weight * saturation, saturation

def group_value(weights_by_direction, assets_by_direction):
    """Значение группы: между РАЗНЫМИ направлениями — насыщающая свёртка.
    Внутри направления активы уже свёрнуты в direction_value."""
    per_dir, prod = {}, 1.0
    for d, assets in assets_by_direction.items():
        p, sat = direction_value(weights_by_direction[d], assets)
        per_dir[d] = {"p": p, "saturation": sat, "assets": len(assets)}
        prod *= (1.0 - p)
    return 1.0 - prod, per_dir

# ------------------------------------------------- загрузка снимков
def load(obj, collector, day=None):
    """Данные сборщика и дата их наблюдения.

    Если дата задана явно - читается строго она.
    Если дата не задана - берётся самый свежий снимок, в котором сборщик
    отработал. Признак не обязан наблюдаться одновременно с остальными: у него
    своя дата, и она возвращается вторым значением, чтобы попасть в карточку.

    Возвращает (данные, дата) или (None, None) - последнее означает
    «не проверено», а не «не обнаружено».
    """
    if day:
        p = snapshot(obj, day, collector)
        return (json.load(open(p))["data"], day) if p.exists() else (None, None)
    d, p = latest_for(obj, collector)
    return (json.load(open(p))["data"], d) if p else (None, None)

# ------------------------------------------------- разбор объекта
def perimeter(obj, domain, day=None, vendor_domains=()):
    """Группа 2 по снимкам DNS и Censys. Возвращает активы, исключённое и диагностику."""
    dns, dns_day = load(obj, "dns", day)
    if dns is None:
        raise FileNotFoundError(f"{obj}: снимка DNS нет ни за одну дату")
    day = day or dns_day
    # Домен для привязки берётся из снимка, а не из конфига объекта.
    # Иначе смена домена в objects.py задним числом делает все прежние имена
    # объекта «чужими», и привязка старых снимков рассыпается.
    domain = dns.get("domain") or domain
    # Censys берётся по своей дате: он запускается отдельно от DNS и часто
    # в другой день, потому что ограничен тарифом.
    cen, cen_day = load(obj, "censys", day)
    if cen is None:
        cen, cen_day = {"hosts": {}, "states": {}}, None
    hosts = cen.get("hosts") or {}
    # Апекс добавляется всегда: addresses заполняется из журнала сертификатов,
    # и при его отказе перечень пуст, хотя адрес известен из записи A.
    addr = dict(dns.get("addresses") or {})
    for ip in (dns.get("a") or []):
        addr.setdefault(ip, []).append(domain)
        addr[ip] = sorted(set(addr[ip]))

    own_assets, excluded, supplier_addrs, unchecked = [], [], [], []
    for ip, own_names in addr.items():
        rec = hosts.get(ip)
        cls, why = attribute(ip, own_names, rec, domain, vendor_domains)
        svc, st, svc_why = censys_services(rec) if rec else ([], "not_checked",
                                                             "адрес не запрашивался")
        row = {"ip": ip, "own_names": own_names, "class": cls, "reason": why,
               "services": svc, "service_state": st, "service_reason": svc_why,
               "asn": censys_asn(rec) if rec else None}
        if cls == "unknown":
            # У оператора нет перечня имён для адреса: принадлежность
            # не установлена. Это not_checked, а не «адрес чужой»:
            # исключение по неизвестности занижало бы оценку молча.
            row["service_state"] = "not_checked"
            row["service_reason"] = why
            unchecked.append(row)
        elif cls == "supplier":
            supplier_addrs.append(row)
        elif cls == "own":
            if st == "confirmed" and svc:
                # Узел с наблюдаемыми службами: актив направления «эксплуатация».
                # Достоверность 3: сам факт узла наблюдаем прямо, а вывод
                # «узел пригоден как вход» остаётся предположением.
                row["asset"] = {"reliability": "A", "credibility": 3}
                own_assets.append(row)
            else:
                unchecked.append(row)
        else:
            excluded.append(row)
    return {"day": day, "dns_day": dns_day, "censys_day": cen_day,
            "own": own_assets, "excluded": excluded,
            "supplier": supplier_addrs, "unchecked": unchecked,
            "mail": mail_channel(dns)}

def vendors_from_fingerprint(obj, day=None):
    """Домены поставщиков из разметки главной страницы. Нужны для распознавания
    инфраструктуры поставщика при привязке адресов.

    Возвращает (домены, поставщики, проверено). Третье значение обязательно:
    если страницу получить не удалось, отсутствие поставщиков означает, что
    разметку НЕ СМОТРЕЛИ, а не что зависимости нет. Без этого различия пробел
    сбора превращается в подтверждённый ноль и занижает оценку."""
    fp, fp_day = load(obj, "fingerprint", day)
    if fp is None:
        return [], [], False
    checked = bool(fp.get("found")) and fp.get("status") != "not_checked"
    vend = fp.get("vendors") or []
    domains = sorted({".".join(v["host"].split(".")[-2:]) for v in vend if v.get("host")})
    return domains, vend, checked


# ------------------------------------------------- группа третьей стороны
def third_party(obj, domain, day=None):
    """Значение группы 3 и его достоверность.

    Достоверность определяется числом НЕЗАВИСИМЫХ наблюдений одной и той же
    зависимости, по шкале Admiralty:

      одно наблюдение  — разметка главной страницы содержит поддомен,
                         названный по объекту на домене поставщика.
                         Это вывод из наблюдения: достоверность 2,
                         «вероятно истинно».
      два наблюдения   — к разметке добавляется атрибуция адреса: имя объекта
                         разрешается в адрес, где оператор сканера видит имена
                         домена поставщика. Источники независимы, поэтому
                         достоверность 1, «подтверждено другими источниками».

    Значение группы при подтверждённой зависимости равно единице: силу связи
    методология числовым коэффициентом не выражает, масштаб влияния несёт вес
    группы, полученный из измеренных данных."""
    # day передаётся дальше как есть: None означает «каждый сборщик по своей
    # свежей дате», а заданная дата — режим воспроизведения одного снимка.
    vendor_domains, vend, fp_checked = vendors_from_fingerprint(obj, day)
    # Наблюдение 1: поддомен, названный по объекту, на домене поставщика
    named = [v for v in vend if v.get("level") == 2]
    # Наблюдение 2: адрес объекта относится к инфраструктуре поставщика
    per = perimeter(obj, domain, day, vendor_domains)
    supplier_addrs = per["supplier"]
    sources = []
    if named:
        sources.append({"kind": "markup",
                        "what": f"поддомен по имени объекта на домене поставщика: "
                                f"{', '.join(v['host'] for v in named)}"})
    if supplier_addrs:
        for row in supplier_addrs:
            sources.append({"kind": "dns_attribution",
                            "what": f"{', '.join(row['own_names'])} разрешается в "
                                    f"{row['ip']}, где оператор сканера видит имена "
                                    f"домена поставщика"})
    if not sources:
        if not fp_checked:
            # Главная страница не получена: разметку не смотрели. Группа остаётся
            # НЕПРОНАБЛЮДЁННОЙ и исключается из свёртки с перенормировкой,
            # а не входит в неё нулём.
            return {"value": None, "status": "not_checked", "credibility": None,
                    "sources": [], "note": "главная страница не получена, разметка "
                                           "не проверена: группа непронаблюдена"}
        return {"value": None, "status": "not_found", "credibility": None,
                "sources": [], "note": "наблюдаемой зависимости от поставщика "
                                       "не обнаружено в проверенных источниках"}
    cred = 1 if len(sources) >= 2 else 2
    return {"value": 1.0, "status": "confirmed", "reliability": "A",
            "credibility": cred, "sources": sources,
            "p": 1.0 * trust("A", cred),
            "note": (f"зависимость подтверждена {len(sources)} независимыми "
                     f"наблюдениями, достоверность {cred}"
                     if cred == 1 else
                     "зависимость наблюдается одним источником, достоверность 2 "
                     "«вероятно истинно»")}


# ------------------------------------------------- покрытые техники по объекту
# Набор покрытых техник свой у каждого объекта. Предикаты построены на службе,
# которую видит сканер, а не на имени узла: имя — предположение о назначении.
REMOTE_ACCESS_SERVICES = ("SSH", "RDP", "VNC", "TELNET", "IPSEC", "OPENVPN",
                          "WIREGUARD", "L2TP", "PPTP")
REMOTE_ACCESS_PORTS = (22, 3389, 5900, 23, 500, 1194, 51820, 1723)

def remote_access(services):
    """T1133: наблюдается ли служба удалённого доступа. Возвращает (да, перечень)."""
    hits = []
    for s in services or []:
        name = str(s.get("service_name") or "").upper()
        port = s.get("port")
        if name in REMOTE_ACCESS_SERVICES or port in REMOTE_ACCESS_PORTS:
            hits.append(f"{port}/{s.get('service_name') or 'не определена'}")
    return bool(hits), hits

def covered_techniques(per, mail, tp_status):
    """Покрытые техники для одного объекта, с основанием по каждой.

    T1190 — эксплуатация публичного приложения: наблюдается служба на своём
            адресе объекта.
    T1133 — внешние службы доступа: среди служб есть служба удалённого
            доступа. Техника отдельная от T1190, и у неё другой профиль
            применяющих её групп.
    T1566 — фишинг: политика почтового канала не отклоняет подделку.
    T1199 — доверенные отношения: зависимость от третьей стороны наблюдаема.
    """
    cov, why = set(), {}
    own = [r for r in per["own"] if "asset" in r]
    if own:
        cov.add("T1190")
        why["T1190"] = f"служб на своих адресах: {sum(len(r['services']) for r in own)}"
    ra = []
    for r in own:
        ok, hits = remote_access(r["services"])
        if ok: ra.append(f"{r['ip']} ({', '.join(hits)})")
    if ra:
        cov.add("T1133")
        why["T1133"] = "службы удалённого доступа: " + "; ".join(ra)
    if any(m["status"] == "confirmed" and (m.get("value_num") or 0) > 0 for m in mail):
        cov.add("T1566")
        why["T1566"] = "политика почтового канала не отклоняет подделку отправителя"
    if tp_status == "confirmed":
        cov.add("T1199")
        why["T1199"] = "зависимость от третьей стороны подтверждена наблюдением"
    return cov, why


# ------------------------------------- инфраструктурная зависимость по ASN
def infra_dependency(per, own_asns=()):
    """Зависимость от владельца инфраструктуры: своё имя объекта разрешается
    в адрес в чужой автономной системе.

    own_asns — автономные системы, принадлежность которых объекту установил
    аналитик по публичным сведениям о владельце AS. Машина наблюдает систему,
    принадлежность приписывает человек, и это видно в достоверности.
    """
    own_asns = set(own_asns)
    foreign = {}
    for r in per["own"] + per["unchecked"]:
        asn = r.get("asn")
        if asn and asn not in own_asns:
            foreign.setdefault(asn, []).append(r["ip"])
    if not foreign:
        return {"status": "not_found", "value": 0.0, "credibility": None,
                "note": ("все свои адреса объекта находятся в автономных системах, "
                         "принадлежность которых объекту установлена: внешнего "
                         "владельца инфраструктуры не наблюдается")}
    return {"status": "confirmed", "value": 1.0, "credibility": 3,
            "asns": {k: v for k, v in foreign.items()},
            "note": ("публичный периметр объекта размещён в чужой автономной "
                     "системе: " + "; ".join(f"{k} ({len(v)} адр.)"
                                             for k, v in foreign.items()))}


# --------------------------------- третья сторона: наблюдаемая глубина доступа
# Глубину доступа несёт достоверность производного утверждения «компрометация
# этой стороны достигает объекта»:
#   1 — поставщик прикладной системы, путь обработки данных: достоверность 1-2
#   2 — посредник, завершающий TLS, путь трафика:            достоверность 3
#   3 — владелец площадки, путь инфраструктуры:              достоверность 5
# Отдельного коэффициента глубины нет: обоснованного значения для него
# источников не найдено.

# Операторы защиты от перегрузки и сети доставки. Перечень курируемый и
# проверяемый: принадлежность автономной системы оператору публична.
EDGE_PROVIDERS = (
    "DDOS-GUARD", "QRATOR", "CLOUDFLARE", "AKAMAI", "FASTLY", "STORMWALL",
    "VARITI", "G-CORE", "GCORE", "IMPERVA", "INCAPSULA", "MYRACLOUD",
    "SUCURI", "CDN77", "BUNNY", "EDGIO", "SELECTEL-CDN", "NGENIX",
)

def asn_org(asn):
    """Владелец автономной системы из её имени.

    Censys отдаёт имя в виде «<обозначение AS> - <владелец>», и у одного
    владельца автономных систем может быть несколько: у «ПАО МегаФон» в нашей
    выборке их три (Cloud-Megafon, MEGAFON-AS, SONICDUO-AS). Дедупликация
    должна идти ПО ВЛАДЕЛЬЦУ: три системы одной компании — одна зависимость,
    а не три. Дедупликация по номеру системы утраивала бы её вклад.
    """
    t = str(asn or "")
    return (t.split(" - ", 1)[1] if " - " in t else t).strip() or t

def is_edge(label):
    """Относится ли имя автономной системы или заголовок сервера к оператору,
    завершающему TLS. Сравнение по верхнему регистру и подстроке: имена
    автономных систем записываются по-разному."""
    u = str(label or "").upper()
    return next((p for p in EDGE_PROVIDERS if p in u), None)

def third_party_depths(obj, per, tp, server_header=None, own_asns=()):
    """Наблюдения третьей стороны по глубинам. Возвращает (активы, разбор).

    Активы пригодны для свёртки варианта Б: у каждого своё доверие, и внутри
    направления они насыщаются к весу направления. Дедупликация идёт
    ПО СТОРОНЕ, а не по адресу: один оператор на трёх адресах — одна
    зависимость, а не три.
    """
    assets, detail = [], []
    own_asns = set(own_asns)

    # ----- глубина 1: поставщик прикладной системы
    if tp["status"] == "confirmed":
        assets.append({"reliability": "A", "credibility": tp["credibility"],
                       "value_num": 1.0, "depth": 1})
        detail.append({"depth": 1, "kind": "поставщик прикладной системы",
                       "credibility": tp["credibility"],
                       "what": "; ".join(s["what"] for s in tp.get("sources", []))})

    # ----- глубина 2: посредник, завершающий TLS
    edges = {}
    for r in per["excluded"] + per["supplier"]:
        p = is_edge(r.get("asn"))
        if p: edges.setdefault(p, []).append(f"{r['ip']} ({r.get('asn')})")
    p = is_edge(server_header)
    if p: edges.setdefault(p, []).append(f"заголовок сервера главной страницы: {server_header}")
    for prov, ev in edges.items():
        assets.append({"reliability": "A", "credibility": 3,
                       "value_num": 1.0, "depth": 2})
        detail.append({"depth": 2, "kind": f"посредник, завершающий TLS: {prov}",
                       "credibility": 3, "what": "; ".join(ev)})

    # ----- глубина 3: владелец площадки, с дедупликацией ПО ВЛАДЕЛЬЦУ
    own_orgs = {asn_org(a) for a in own_asns}
    plats, systems = {}, {}
    addressable = per["own"] + per["unchecked"]
    for r in addressable:
        a = r.get("asn")
        if a and asn_org(a) not in own_orgs and not is_edge(a):
            plats.setdefault(asn_org(a), []).append(r["ip"])
            systems.setdefault(asn_org(a), set()).add(a)
    for org, ips in plats.items():
        assets.append({"reliability": "A", "credibility": 5,
                       "value_num": 1.0, "depth": 3})
        sysn = sorted(systems[org])
        detail.append({"depth": 3, "kind": f"владелец площадки: {org}",
                       "credibility": 5,
                       # Свидетельство сжато: перечень номеров систем занимает
                       # полстроки и ничего не добавляет к утверждению.
                       "what": f"{len(ips)} собственных "
                               f"{'адрес' if len(ips)%10==1 and len(ips)%100!=11 else 'адреса' if len(ips)%10 in (2,3,4) and len(ips)%100 not in (12,13,14) else 'адресов'}"
                               f" объекта в "
                               f"{len(sysn)} его автономных "
                               f"{'системе' if len(sysn)%10==1 and len(sysn)%100!=11 else 'системах'}"})
    if not addressable:
        # Своих адресов у объекта не наблюдается вовсе: площадку установить
        # не из чего. Глубина 3 НЕ ПРОВЕРЕНА, и значение группы — нижняя
        # граница, о чём говорится в разборе.
        detail.append({"depth": None, "kind": "глубина 3 не проверена",
                       "what": "собственных адресов объекта не наблюдается, "
                               "владельца площадки установить не из чего"})

    if not assets:
        why = ("ни один канал наблюдения не дал зависимости"
               if tp["status"] != "not_checked" else
               "разметка главной страницы не получена, прочие каналы зависимости не дали")
        return [], [{"depth": None, "kind": "не обнаружено", "what": why,
                     "tp_status": tp["status"]}]
    return assets, detail
