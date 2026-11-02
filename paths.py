"""Все пути в одном месте и относительно корня пакета.
"""
import os, pathlib
ROOT = pathlib.Path(__file__).resolve().parent
# Каталог данных задаётся переменной TARGETMAP_DATA: так один и тот же код
# работает и на рабочем наборе, и на обезличенном.
DATA = ROOT / os.environ.get("TARGETMAP_DATA", "data")
RAW  = DATA / "raw"                    # data/raw/<объект>/<дата>/<сборщик>.json
REG  = DATA / "registries"             # реестры ОМС
DB   = DATA / "observations.db"
OUT  = DATA / "exports"                # карточки, сводная таблица, лог ненайденного

def snapshot(obj: str, day: str, collector: str) -> pathlib.Path:
    return RAW / obj / day / f"{collector}.json"

def latest_day(obj: str) -> str | None:
    """Самый свежий снимок объекта. Нужен, чтобы не писать дату руками."""
    d = RAW / obj
    days = sorted(p.name for p in d.iterdir() if p.is_dir()) if d.exists() else []
    return days[-1] if days else None

def latest_for(obj: str, collector: str):
    """Самый свежий снимок, в котором отработал сборщик.

    Поскольку сборщики запускаются независимо, один может отработать сегодня, 
    другой отказать и быть переснят завтра.

    Наблюдение датируется само: у каждого признака своя дата снимка, и она
    записывается рядом со значением. Разброс дат показывается через spread().

    Возвращает (дата, путь) или (None, None), если сборщик не отрабатывал ни
    разу: это состояние «не проверено», а не «не обнаружено».
    """
    d = RAW / obj
    if not d.exists():
        return None, None
    for day in sorted((p.name for p in d.iterdir() if p.is_dir()), reverse=True):
        p = snapshot(obj, day, collector)
        if p.exists():
            return day, p
    return None, None

def spread(obj: str, collectors=("dns", "crtsh", "censys", "dnstwist", "fingerprint")):
    """Разброс дат наблюдения по объекту: {сборщик: дата}."""
    return {c: latest_for(obj, c)[0] for c in collectors}

SECTOR = "_sector"                     # снимки уровня сегмента, а не объекта

def sector_snapshot(collector: str, day: str | None = None):
    """Фон сегмента собирается один раз на выборку, поэтому лежит отдельно
    от объектов."""
    day = day or latest_day(SECTOR)
    return RAW / SECTOR / day / f"{collector}.json"
