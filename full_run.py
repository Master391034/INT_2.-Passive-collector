"""Расчёт по всей оценочной выборке. Читает снимки, ничего не скачивает."""
import json, sys
from normalize import (perimeter, third_party, vendors_from_fingerprint, group_value,
                       covered_techniques, infra_dependency, third_party_depths)
from reference import REV, ADDR, percentile
from objects import BY_KEY, EVALUATED, REVENUE, ADDRESSES
from calc import SPEC_BASE, direction_weights, group_weights, interest, applicability
from paths import sector_snapshot, latest_day
import oms

attack = json.load(open(sector_snapshot("attack")))["data"]
from inputs import load
MANUAL_ALL = load("manual.json", default={}, quiet=True) or {}
MANUAL = MANUAL_ALL.get("objects") or {}
OWN_ASNS = MANUAL_ALL.get("own_asns") or {}
# Значение по умолчанию. Рабочий набор считает covered_techniques по объекту.
COVERED = {"T1190","T1566","T1199"}
# Устаревший флаг плоского канала ASN; глубины его заменили.
USE_INFRA = __import__('os').environ.get('USE_INFRA','0') == '1'
FON = 0.10
ESC = {"none":1,"claim":3,"independent":4,"official":5}
# Шкала уровней оснований. Сами наблюдения лежат в data/objects.json:
# это данные об объекте, а не параметр модели.
OBJECT_OBS = {o["key"]: (o["observation"]["level"], o["observation"]["why"])
              for o in EVALUATED if o.get("observation")}
KEYS = [o["key"] for o in EVALUATED]
# Реестры читаются лениво: когда признаки ОМС запечены в manual.json
# (обезличенный набор), выгрузки ФОМС не нужны вовсе.
_REG_CACHE = {}
def _registries():
    if not _REG_CACHE:
        _REG_CACHE["fed"], _REG_CACHE["reg"] = oms.federal(), oms.regional()
    return _REG_CACHE["fed"], _REG_CACHE["reg"]

def oms_features(inn):
    """Признаки ОМС. Без запечённых значений и без выгрузок реестров признаки
    остаются непронаблюдёнными, а не обнуляются."""
    if oms.baked().get(inn) is not None:
        return oms.features_for(inn)
    try:
        return oms.features_for(inn, *_registries())
    except (FileNotFoundError, OSError):
        return []


FULL_MIN = 0.5   # ниже половины веса семейств источников известного меньше, чем неизвестного

def category(index, full_min, escalate, q3, q1):
    """Категория по таблице методологии. Порядок проверок важен: эскалация
    и низкая полнота предшествуют оценке по индексу."""
    if escalate:
        return ("ручная проверка по эскалации",
                "подтверждённое свидетельство уровня 4 или 5 — независимо от индекса")
    low = full_min < FULL_MIN
    high = index >= q3
    if high and low:
        return ("требует доразведки",
                "значимые признаки при неполной картине: приоритетно расширение наблюдения")
    if low:
        return ("недостаточно данных",
                "объект непрозрачен для пассивного наблюдения, оценка не построена")
    if high:
        return ("наблюдение",
                "устойчивые предпосылки интереса без признаков текущей подготовки")
    if index <= q1:
        return ("фоновый уровень",
                "наблюдаемых оснований для выделения объекта нет")
    return ("фоновый уровень", "средний индекс при достаточной полноте")

def build(key, spec=SPEC_BASE):
    o = BY_KEY[key]
    dirw, grw = direction_weights(spec), group_weights(spec)
    vd, _, _ = vendors_from_fingerprint(key)
    per = perimeter(key, o["domain"], vendor_domains=vd)
    tp  = third_party(key, o["domain"])

    assets = {"exploit":[dict(r["asset"], value_num=1.0) for r in per["own"] if "asset" in r],
              "phishing":[]}
    mv = [m for m in per["mail"] if m["status"]=="confirmed" and m.get("value_num")]
    if mv:
        b = max(mv, key=lambda m: m["value_num"])
        assets["phishing"] = [{"reliability":b["reliability"],
                               "credibility":b["credibility"],"value_num":b["value_num"]}]
    P2,_ = group_value({k:dirw[k] for k in assets}, assets)
    # Группа 3: три глубины доступа, каждая со своей достоверностью.
    # Складываются внутри направления с насыщением, как прочие активы.
    infra = infra_dependency(per, (OWN_ASNS.get(key) or {}).get("asns") or ())
    # Заголовок сервера главной страницы — второй, независимый от DNS канал
    # обнаружения посредника, завершающего TLS.
    try:
        _fp, _ = __import__("normalize").load(key, "fingerprint")
        srv = ((_fp or {}).get("headers") or {}).get("server")
    except Exception:
        srv = None
    tp_assets, tp_detail = third_party_depths(
        key, per, tp, srv, (OWN_ASNS.get(key) or {}).get("asns") or ())
    groups = {2:P2}
    if tp_assets:
        P3,_ = group_value({"third_party":1.0}, {"third_party":tp_assets})
        groups[3] = P3
    elif tp["status"] == "not_checked":
        # Разметку получить не удалось И ни один другой канал не дал
        # наблюдения: группа остаётся непронаблюдённой.
        P3 = None
    else:
        groups[3] = 0.0; P3 = 0.0

    den = sum(grw[g] for g in groups)
    base = sum(grw[g]*v for g,v in groups.items())/den
    # Перенормировка повышает базу относительно наблюдённого нуля, поэтому
    # её всегда сопровождает доля веса пронаблюдённых групп.
    full_reach = den / sum(grw.values())

    # признаки интереса
    omsf = {r["feature"]: r for r in oms_features(o["inn"])}
    man  = MANUAL.get(key, {})
    crit = omsf.get("INT.CRIT",{}).get("value_num")
    crit_src = "реестр ТРМО"
    if crit is None:
        crit = man.get("INT.CRIT"); crit_src = "аналитик"
    # INT.DATA — перцентиль числа адресов приёма. Прокси слабый, достоверность 2.
    vals = {"INT.PAY": percentile(REVENUE[key], REV),
            "INT.DATA": percentile(ADDRESSES[key], ADDR) if ADDRESSES.get(key) else None,
            "INT.GOV": omsf.get("INT.GOV",{}).get("value_num"),
            "INT.CRIT": crit}
    vals = {k:v for k,v in vals.items() if v is not None}

    lvl, why = OBJECT_OBS.get(key, ("none","объектных наблюдений не найдено"))
    out = {"brand":o["brand"], "P2":P2, "P3":groups.get(3), "base":base,
           "own":len([r for r in per["own"] if "asset" in r]),
           "unchecked":len(per["unchecked"]), "excluded":len(per["excluded"]),
           "supplier":len(per["supplier"]), "tp_cred":tp.get("credibility"),
           "vals":vals, "crit_src":crit_src, "mail":per["mail"],
           "full_reach":full_reach, "groups_seen":sorted(groups),
           "ev":ESC[lvl], "escalate":ESC[lvl]>=4, "obs_why":why,
           "oms":omsf.get("INT.GOV",{}).get("value_text",""), "idx":{}, "full":{},
           "infra":infra, "tp_status":tp["status"],
           "tp_detail":tp_detail, "server":srv}
    cov, cov_why = covered_techniques(per, per["mail"], tp["status"])
    if tp_assets:
        # T1199 покрыта зависимостью любой глубины.
        cov.add("T1199")
        cov_why["T1199"] = "; ".join(f"глубина {d['depth']}: {d['kind']}"
                                     for d in tp_detail if d.get("depth"))
    out_cov = (sorted(cov), cov_why)
    for actor in ("criminal","apt"):
        I, full = interest(vals, spec["interest"][actor])
        app,_,_,_ = applicability(attack, cov or COVERED, actor)
        out["idx"][actor] = (I*100 * base*app*100 * FON*100)**(1/3)
        out["full"][actor] = full
        out.setdefault("I",{})[actor] = I
    # Индекс — произведение, поэтому категорию ограничивает минимум полнот.
    out["full_min"] = min(min(out["full"].values()), full_reach)
    out["covered"], out["covered_why"] = out_cov
    return out

if __name__ == "__main__":
    R = {k: build(k) for k in KEYS}
    print("ОЦЕНОЧНАЯ ВЫБОРКА, базовая спецификация (DBIR 2026)\n")
    print(f"{'объект':<20}{'ОМС':>5}{'крит':>6}{'P2':>8}{'P3':>8}{'база':>7}"
          f"{'крим':>7}{'APT':>7}{'п.инт':>7}{'п.дост':>8}{'ПОЛН':>7}{'ур':>4}{'эск':>5}")
    print("-"*106)
    for k in sorted(KEYS, key=lambda x: -max(R[x]["idx"].values())):
        r = R[k]
        # Непронаблюдённый признак печатается прочерком, а не нулём: ноль —
        # это утверждение «признака нет», и путать его с пробелом нельзя.
        gov = r['vals'].get('INT.GOV')
        crit = r['vals'].get('INT.CRIT')
        print(f"{r['brand'][:19]:<20}{('—' if gov is None else 'да' if gov else 'нет'):>5}"
              f"{('—' if crit is None else '%.2f' % crit):>6}"
              f"{r['P2']:>8.4f}{(('%.4f'%r['P3']) if r['P3'] is not None else '—'):>8}"
              f"{r['base']*100:>7.1f}{r['idx']['criminal']:>7.2f}{r['idx']['apt']:>7.2f}"
              f"{r['full']['criminal']:>7.3f}{r['full_reach']:>8.3f}{r['full_min']:>7.3f}"
              f"{r['ev']:>4}{('ДА' if r['escalate'] else '-'):>5}")
    print()
    print("ПОРЯДОК: " + " > ".join(R[k]["brand"] for k in
          sorted(KEYS, key=lambda x: -max(R[x]["idx"].values()))))

def specs():
    """Спецификации весов для проверки устойчивости.

    Вынесено из sensitivity() на уровень модуля: перечень спецификаций нужен
    и для проверки устойчивости, и для отчёта о том, какие позиции порядка
    сохраняются. Два перечня разошлись бы при любой правке.
    """
    import copy
    def spec(name, dirs, tp, inter=None):
        s = copy.deepcopy(SPEC_BASE); s["name"]=name
        s["directions_raw"]=dirs; s["third_party_raw"]=tp
        if inter: s["interest"]=inter
        return s
    EQ = {a:{k:1/6 for k in SPEC_BASE["interest"]["criminal"]} for a in SPEC_BASE["interest"]}
    return [
     spec("DBIR 2026 — базовая",       {"exploit":20,"phishing":14,"credentials":11}, 32),
     spec("Solar 4RAYS",               {"exploit":30,"phishing":15,"credentials":30}, 24),
     spec("PT CODE RED 2026",          {"exploit":20,"phishing":14,"credentials":11},  4),
     spec("Информзащита, медицина РФ", {"exploit":44,"phishing":18,"credentials":28},  6),
     spec("равные веса ИНТЕРЕСА",      {"exploit":20,"phishing":14,"credentials":11}, 32, inter=EQ),
    ]

def stability():
    """По каждой позиции порядка: сохраняется она на всех спецификациях или нет.

    Утверждать «порядок устойчив» целиком нельзя: устойчивость бывает
    позиционной. Эта функция отвечает на вопрос попозиционно, чтобы в отчёт
    попало ровно то, что проверено.
    """
    rows = []
    for s in specs():
        R = {k: max(build(k, s)["idx"].values()) for k in KEYS}
        rows.append((s["name"], sorted(KEYS, key=lambda k: -R[k]), R))
    out = []
    for pos in range(len(KEYS)):
        occ = {o[pos] for _, o, _ in rows}
        gaps = [abs(R[o[pos]] - R[o[pos+1]]) for _, o, R in rows if pos+1 < len(o)]
        out.append({"position": pos+1, "stable": len(occ) == 1,
                    "objects": sorted(occ),
                    "min_gap_to_next": min(gaps) if gaps else None})
    return out, rows

def tiers():
    """Устойчивые ГРУППЫ вместо строгого порядка.

    Зачем. Строгий порядок утверждать нельзя, когда он меняется между
    спецификациями, но из этого не следует, что не утверждается ничего:
    множество объектов, занимающих первые k мест, может сохраняться, даже
    если порядок внутри него нет. Такое утверждение слабее и честнее, и для
    задачи наблюдения достаточно: оно говорит, на что смотреть первым.

    Возвращает перечень (k, устойчиво, множество) по каждому k от 1 до n-1.
    """
    rows = []
    for sp in specs():
        R = {k: max(build(k, sp)["idx"].values()) for k in KEYS}
        rows.append(sorted(KEYS, key=lambda y: -R[y]))
    out = []
    for k in range(1, len(KEYS)):
        sets = {frozenset(o[:k]) for o in rows}
        out.append({"k": k, "stable": len(sets) == 1,
                    "set": sorted(next(iter(sets))) if len(sets) == 1 else None})
    return out

def sensitivity():
    SPECS = specs()
    print("\n\nУСТОЙЧИВОСТЬ ПОРЯДКА ПО СПЕЦИФИКАЦИЯМ\n")
    # Короткие подписи для таблиц: берутся из названия объекта, а не задаются
    # перечнем, иначе таблицы ломаются при смене набора данных.
    SHORT = {o["key"]: (o["brand"][:9] if len(o["brand"]) > 10 else o["brand"])
             for o in EVALUATED}
    hdr = "".join(f"{SHORT[k]:>9}" for k in KEYS)
    print(f"{'спецификация':<28}{hdr}   порядок")
    print("-"*118)
    orders = []
    for s in SPECS:
        R = {k: build(k, s) for k in KEYS}
        best = {k: max(R[k]["idx"].values()) for k in KEYS}
        order = sorted(KEYS, key=lambda x: -best[x])
        orders.append(order)
        print(f"{s['name']:<28}" + "".join(f"{best[k]:>9.2f}" for k in KEYS)
              + "   " + " > ".join(SHORT[k] for k in order))
    print()
    first = [o[0] for o in orders]
    print(f"  первое место: {'УСТОЙЧИВО, ' + SHORT[first[0]] if len(set(first))==1 else 'МЕНЯЕТСЯ: ' + ', '.join(SHORT[f] for f in dict.fromkeys(first))}")
    same = all(o == orders[0] for o in orders)
    print(f"  полный порядок: {'совпадает во всех спецификациях' if same else 'различается между спецификациями'}")
    if not same:
        for i, o in enumerate(orders[1:], 1):
            moved = [SHORT[k] for k in KEYS if o.index(k) != orders[0].index(k)]
            if moved: print(f"    {SPECS[i]['name']}: сместились {', '.join(moved)}")
    # Устойчивость бывает частичной, поэтому проверяется попозиционно.
    print("\n  ПОПОЗИЦИОННО:")
    pos_rows, _ = stability()
    for r in pos_rows:
        g = f"{r['min_gap_to_next']:.2f}" if r["min_gap_to_next"] is not None else "—"
        names = ", ".join(SHORT[k] for k in r["objects"])
        print(f"    позиция {r['position']}: "
              f"{'УСТОЙЧИВА' if r['stable'] else 'меняется '}  "
              f"мин. разрыв со следующей {g:>6}   {names}")
    print("    Устойчивость позиции и величина разрыва — разные свойства: "
          "позиция может сохраняться при малом разрыве и меняться при большом.")
    print("\n  УСТОЙЧИВЫЕ ГРУППЫ (множество первых k мест, без порядка внутри):")
    for t in tiers():
        mark = "УСТОЙЧИВА  " if t["stable"] else "не устойчива"
        names = ", ".join(SHORT[x] for x in t["set"]) if t["set"] else "—"
        print(f"    первые {t['k']}: {mark} {names}")
    print("    Строгий порядок не утверждается там, где он меняется; "
          "утверждается то, что сохраняется на всех спецификациях.")

def quartiles():
    """Границы четвертей по РАСПРЕДЕЛЕНИЮ ВЫБОРКИ, а не по назначенным числам.

    Категория — суждение сравнительное: «выше трёх четвертей выборки» имеет
    смысл, а «выше 25 баллов» не имеет, пока не сказано, откуда 25. Поэтому
    границы пересчитываются вместе с выборкой, и при её изменении меняются.
    Следствие, которое надо называть прямо: категория объекта зависит от
    состава выборки и вне неё не переносится.
    """
    best = {k: max(build(k)["idx"].values()) for k in KEYS}
    vals = sorted(best.values()); n = len(vals)
    return vals[int(0.75*(n-1))], vals[int(0.25*(n-1))]

def categories():
    R = {k: build(k) for k in KEYS}
    best = {k: max(R[k]["idx"].values()) for k in KEYS}
    q3, q1 = quartiles()
    print("\n\nКАТЕГОРИИ ПРИОРИТЕТА\n")
    print(f"  границы по распределению выборки: верхняя четверть >= {q3:.2f}, "
          f"нижняя четверть <= {q1:.2f}")
    print(f"  порог достаточной полноты {FULL_MIN}: ниже него пронаблюдено менее "
          f"половины веса семейств источников")
    print()
    print(f"{'объект':<22}{'индекс':>8}{'полнота':>9}{'ур':>4}  категория")
    print("-"*96)
    for k in sorted(KEYS, key=lambda x: -best[x]):
        r = R[k]; v = best[k]
        cat, why = category(v, r["full_min"], r["escalate"], q3, q1)
        print(f"{r['brand'][:21]:<22}{v:>8.2f}{r['full_min']:>9.3f}{r['ev']:>4}  {cat}")
        print(f"{'':43}  {why}")

if __name__ == "__main__":
    sensitivity(); categories()
