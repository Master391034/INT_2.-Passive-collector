"""Данные, вносимые аналитиком: что нужно, где лежит и что будет без этого.

Правило то же, что для сетевых источников: отсутствие входных данных — это
состояние «не проверено», а не отказ программы. Признак без своего источника
исключается из расчёта с перенормировкой, и это видно в полноте наблюдения.
Падать программа имеет право только без перечня объектов: без него не задана
сама задача.

Запуск `python3 inputs.py` печатает, что найдено, чего нет и чем это обернётся.
"""
import json, pathlib
from paths import DATA, REG

INPUTS = [
    {"file": "objects.json", "required": True,
     "what": "перечень объектов: ключ, ИНН, домен, название, выручка, "
             "число адресов приёма, объектные наблюдения",
     "feeds": "вся задача",
     "without": "работа невозможна: не задан перечень оцениваемых организаций"},
    {"file": "reference.json", "required": False,
     "what": "референсное распределение: ИНН, выручка, адреса приёма по "
             "юрлицам сегмента",
     "feeds": "INT.PAY, INT.DATA",
     "without": "признаки объёма не переводятся в перцентиль и становятся "
                "непронаблюдёнными: исключаются с перенормировкой, полнота падает"},
    {"file": "manual.json", "required": False,
     "what": "вносимое аналитиком: шкала и значения критичности услуг, "
             "наблюдения вне индекса, свои автономные системы, запечённые "
             "признаки ОМС",
     "feeds": "INT.CRIT, глубина 3, наблюдения карточки",
     "without": "критичность услуг непронаблюдена; все автономные системы "
                "считаются чужими; наблюдений вне индекса нет"},
    {"dir": "registries", "required": False,
     "what": "выгрузки реестров ОМС: федеральный (.xlsx) и территориальные",
     "feeds": "INT.GOV, INT.CRIT по реестру",
     "without": "участие в госпрограммах непронаблюдено, если признак не "
                "запечён в manual.json (ключ oms_baked)"},
    {"dir": "raw", "required": False,
     "what": "снимки сборщиков: data/raw/<объект>/<дата>/<сборщик>.json",
     "feeds": "вся достижимость",
     "without": "достижимость непронаблюдена; собрать — run_object.py"},
]


def present(item):
    p = DATA / (item.get("file") or item["dir"])
    if item.get("file"):
        return p.exists(), p
    return (p.exists() and any(p.iterdir())), p


def load(name, default=None, quiet=False):
    """Чтение необязательного файла данных. Отсутствие — не ошибка."""
    p = DATA / name
    if not p.exists():
        if not quiet:
            print(f"! нет {p}: соответствующие признаки будут непронаблюдёнными")
        return default
    return json.load(open(p, encoding="utf-8"))


def require(name):
    """Чтение обязательного файла. Сообщение вместо трассировки стека."""
    p = DATA / name
    if not p.exists():
        raise SystemExit(
            f"\nНе найден обязательный файл: {p}\n"
            f"Это перечень оцениваемых организаций, без него задача не задана.\n"
            f"Образец структуры: data_demo/{name}\n"
            f"Каталог данных задаётся переменной TARGETMAP_DATA "
            f"(сейчас {DATA.name}).\n")
    return json.load(open(p, encoding="utf-8"))


def status(verbose=True):
    """Состояние входных данных. Возвращает список отсутствующего."""
    missing = []
    if verbose:
        print(f"Каталог данных: {DATA}\n")
    for it in INPUTS:
        ok, p = present(it)
        if not ok:
            missing.append(it)
        if verbose:
            mark = "есть      " if ok else ("НЕТ, нужен" if it["required"] else "нет       ")
            print(f"[{mark}] {p.name}")
            print(f"             {it['what']}")
            print(f"             питает: {it['feeds']}")
            if not ok:
                print(f"             без него: {it['without']}")
            print()
    if verbose:
        hard = [m for m in missing if m["required"]]
        if hard:
            print("Работа невозможна: " +
                  ", ".join(m.get("file") or m["dir"] for m in hard))
        elif missing:
            print("Расчёт выполним. Признаки без своих источников будут "
                  "непронаблюдёнными и уйдут в лог ненайденного, а полнота "
                  "наблюдения это покажет.")
        else:
            print("Все входные данные на месте.")
    return missing


if __name__ == "__main__":
    status()
