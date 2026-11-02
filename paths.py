"""Все пути в одном месте и относительно корня пакета.
Так код запускается из любой папки и не зависит от того, где лежит пакет."""
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
    """Самый свежий снимок, В КОТОРОМ ЭТОТ СБОРЩИК ОТРАБОТАЛ.

    Зачем отдельно от latest_day. Сборщики запускаются независимо: один может
    отработать сегодня, другой отказать и быть переснят завтра. Если признак
    брать из самой свежей ПАПКИ, то повторный запуск двух сборщиков превращает
    третий в «не проверено», хотя его наблюдение существует и имеет дату.
    Это стирало бы уже полученные данные самим фактом нового прогона.

    Наблюдение датируется само: у каждого признака своя дата снимка, и она
    записывается рядом со значением. Поэтому допустимо собирать картину
    объекта из снимков разных дней — но разброс дат надо показывать, а не
    скрывать, чем занимается spread() ниже.

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
    """Разброс дат наблюдения по объекту: {сборщик: дата}. Нужен, чтобы
    смешивание снимков разных дней было видно в карточке, а не молчаливо."""
    return {c: latest_for(obj, c)[0] for c in collectors}

SECTOR = "_sector"                     # снимки уровня сегмента, а не объекта

def sector_snapshot(collector: str, day: str | None = None):
    """Фон сегмента собирается один раз на выборку, поэтому лежит отдельно
    от объектов: внутри прогона объекта он давал бы разным объектам разный фон
    из-за разного времени запроса."""
    day = day or latest_day(SECTOR)
    return RAW / SECTOR / day / f"{collector}.json"
