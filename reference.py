"""Референсное распределение: один ИНН по ОКВЭД 86.10, строка 2110 ГИР БО.
Признаки объёма переводятся в перцентиль этого распределения.
Адреса приёма — уникальные адреса, подтверждённые для конкретного юрлица.
Объект external в референс не входит: он оценивается подстановкой в шкалу.

Без файла референса перцентиль не определён, и признаки объёма становятся
непронаблюдёнными: распределения, относительно которого они сравниваются,
просто нет.
"""
from inputs import load

_d = load("reference.json", default={"reference": [], "external": None}, quiet=True)
REFERENCE = [(r["brand"], r["inn"], r["revenue"], r["addresses"])
             for r in _d.get("reference") or []]
_e = _d.get("external")
EXTERNAL = (_e["brand"], _e["inn"], _e["revenue"], _e["addresses"]) if _e else None

AVAILABLE = bool(REFERENCE)

def percentile(value, column):
    """Доля объектов референса строго ниже значения. Нормировка на n, а не
    на n-1: объект вне референса тоже должен попадать в [0, 1].
    Возвращает None, когда сравнивать не с чем: это «не проверено»."""
    if value is None:
        return None
    vals = sorted(v for v in column if v is not None)
    if not vals:
        return None
    return sum(1 for v in vals if v < value) / len(vals)

REV = [r[2] for r in REFERENCE]
ADDR = [r[3] for r in REFERENCE]
