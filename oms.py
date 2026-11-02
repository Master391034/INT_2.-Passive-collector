"""Извлечение признаков из реестров ОМС.

Федеральный реестр (единый по РФ) даёт: наличие в ОМС, форму собственности,
число подразделений в ОМС, субъекты присутствия, дату включения.
Региональные ТРМО дают условия и профиль медицинской помощи.

Признак INT.DATA отсюда не берётся."""
import openpyxl
from collections import defaultdict
from paths import REG

OKFS = {"16":"частная","13":"субъекта РФ","12":"федеральная","23":"иностранная",
        "14":"муниципальная","34":"смешанная","32":"смешанная без гос. участия",
        "41":"обществ. объединений","49":"прочая"}

# Шкала критичности услуг: условия помощи -> уровень. Уровень 4 («единственный
# в территории») из реестра не выводится: код территории в файле региональный.
CRIT_SCALE = [
    ({"Стационарно"},                      0.75, "стационар с круглосуточным пребыванием"),
    ({"В дневном стационаре"},             0.50, "дневной стационар, плановое лечение"),
    ({"Амбулаторно"},                      0.25, "амбулаторная помощь, прерывание переносимо"),
]

def _rows(path, header_rows):
    wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
    ws = wb.worksheets[0]
    for i, r in enumerate(ws.iter_rows(values_only=True), 1):
        if i <= header_rows: continue
        yield [('' if c is None else str(c)).strip() for c in r]

def federal():
    """Федеральный реестр: ключ — ИНН."""
    path = REG / "oms_federal.xlsx"
    wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
    ws = wb.worksheets[0]
    H = {}
    for r in ws.iter_rows(values_only=True):
        H = {str(c).strip(): j for j, c in enumerate(r) if c}; break
    out = defaultdict(lambda: {"rows":0,"subj":set(),"vid":set(),"okfs":"","date":"","name":""})
    for c in _rows(path, 1):
        if len(c) <= H["INN"]: continue
        inn = c[H["INN"]]
        if not inn.isdigit(): continue
        o = out[inn]; o["rows"] += 1
        o["subj"].add(c[H["SUBJ"]]); o["vid"].add(c[H["VID_MO"]])
        o["okfs"] = o["okfs"] or c[H["OKFS"]]
        o["date"] = o["date"] or c[H["D_BEGIN_OMS"]]
        o["name"] = o["name"] or c[H["NAM_MOK"]]
    return out

def regional():
    """Региональные ТРМО: условия и профиль помощи. Шапка в три яруса,
    колонки фиксированы шаблоном ЕГИСЗ: 7 ИНН, 21 адрес, 28 условия, 29 профиль."""
    files = {"Московская обл.":"trmo_mo.xlsx","Санкт-Петербург":"trmo_spb.xlsx",
             "Краснодарский кр.":"trmo_krd.xlsx"}
    out = defaultdict(lambda: defaultdict(lambda: {"addr":set(),"cond":set(),"prof":set()}))
    for region, fn in files.items():
        for c in _rows(REG / fn, 3):
            if len(c) < 30 or not c[7].isdigit(): continue
            o = out[c[7]][region]
            if c[21]: o["addr"].add(c[21])
            for x in c[28].split(","):
                if x.strip(): o["cond"].add(x.strip())
            if c[29]: o["prof"].add(c[29])
    return out

def criticality(conditions: set):
    """Уровень критичности по условиям помощи. Берётся НАИВЫСШИЙ применимый."""
    for need, value, why in CRIT_SCALE:
        if need & conditions:
            return value, why
    return None, "условия помощи не установлены"

def baked():
    """Запечённые признаки ОМС из data/manual.json.

    Нужны там, где реестров нет: выгрузки ФОМС — большие файлы сторонних
    организаций, и обезличенный набор данных обходится без них.
    """
    from inputs import load
    return (load("manual.json", default={}, quiet=True) or {}).get("oms_baked") or {}

def features_for(inn: str, fed=None, reg=None):
    """Признаки для одного ИНН. Возвращает список записей наблюдений."""
    bk = baked().get(inn)
    if bk is not None:
        return bk
    fed = fed if fed is not None else federal()
    reg = reg if reg is not None else regional()
    rec = []
    if inn in fed:
        o = fed[inn]
        rec.append(dict(feature="INT.GOV", value_num=1.0, status="confirmed",
                        source="oms_federal", reliability="A", credibility=1,
                        predicate="passed",
                        value_text=f"в ОМС с {o['date']}, субъектов {len(o['subj'])}, "
                                   f"подразделений {o['rows']}"))
        rec.append(dict(feature="INT.FOREIGN",
                        value_num=1.0 if o["okfs"] in ("23","34") else 0.0,
                        status="confirmed", source="oms_federal",
                        reliability="A", credibility=1, predicate="not_applicable",
                        value_text=f"ОКФС {o['okfs']}: {OKFS.get(o['okfs'],'не расшифрован')}",
                        pred_reason="признака иностранного участия в матрице интереса нет; "
                                    "собран для развилок"))
    else:
        rec.append(dict(feature="INT.GOV", value_num=0.0, status="not_found",
                        source="oms_federal", reliability="A", credibility=1,
                        predicate="passed",
                        value_text="в федеральном реестре ОМС отсутствует",
                        pred_reason="источник проверен, результат отрицательный: "
                                    "реестр федеральный, регионы перебирать не нужно"))
    cond = set()
    regions_seen = []
    for region, rv in reg.get(inn, {}).items():
        cond |= rv["cond"]; regions_seen.append(region)
    if cond:
        v, why = criticality(cond)
        rec.append(dict(feature="INT.CRIT", value_num=v, status="confirmed",
                        source="trmo:" + ",".join(regions_seen),
                        reliability="A", credibility=1, predicate="passed",
                        value_text=f"{'/'.join(sorted(cond))} -> {why}"))
    else:
        rec.append(dict(feature="INT.CRIT", value_num=None, status="not_checked",
                        source="trmo", reliability=None, credibility=None,
                        predicate="not_applicable",
                        value_text="нет в трёх проверенных ТРМО",
                        pred_reason="ТРМО ведутся по субъектам; проверены три. "
                                    "Отсутствие в них не означает отсутствия в других"))
    return rec
