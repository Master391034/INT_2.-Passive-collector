"""Калькулятор индекса приоритета наблюдения.
Читает наблюдения, применяет спецификацию весов, печатает все промежуточные
величины, чтобы любой шаг можно было проверить вручную."""
import json, math
from features import RELIABILITY, CREDIBILITY

# ---------- Спецификация весов (базовая: DBIR 2026, срез здравоохранения) ----------
SPEC_BASE = {
  "name": "DBIR 2026, срез здравоохранения (NAICS 62), n=1438",
  # доли направлений первичного доступа, в процентах из источника
  "directions_raw": {"exploit": 20, "phishing": 14, "credentials": 11},
  # доля инцидентов с участием третьей стороны, из того же источника
  "third_party_raw": 32,
  # веса признаков интереса, метод анализа иерархий (уровень 3: только наше)
  "interest": {
    "criminal":   {"INT.PAY":0.3643,"INT.DATA":0.2587,"INT.PUB":0.0384,
                   "INT.GOV":0.0634,"INT.CRIT":0.1755,"INT.LINK":0.0997},
    "hacktivist": {"INT.PAY":0.0557,"INT.DATA":0.0959,"INT.PUB":0.4028,
                   "INT.GOV":0.1521,"INT.CRIT":0.2559,"INT.LINK":0.0376},
    "apt":        {"INT.PAY":0.0631,"INT.DATA":0.1751,"INT.PUB":0.0421,
                   "INT.GOV":0.3641,"INT.CRIT":0.1146,"INT.LINK":0.2410},
  },
}

def direction_weights(spec):
    """Нормировка долей направлений: они делят одно множество известных векторов входа."""
    d = spec["directions_raw"]; s = sum(d.values())
    return {k: v/s for k, v in d.items()}

def group_weights(spec):
    """Веса групп. Компрометация - из доли учётных данных, периметр - из суммы
    эксплуатации и фишинга, третья сторона - из доли инцидентов с третьей стороной.
    """
    d = spec["directions_raw"]; tp = spec["third_party_raw"]
    raw = {1: d["credentials"], 2: d["exploit"] + d["phishing"], 3: tp}
    s = sum(raw.values())
    return {k: v/s for k, v in raw.items()}

def trust(rel, cred):
    """Поправка на доверие: надёжность источника x достоверность сведения, раздельно."""
    return RELIABILITY.get(rel, 1.0) * CREDIBILITY.get(cred, 1.0)

def group_value(obs, dirw):
    """Значение группы. Внутри направления берётся максимум: несколько свойств
    одного направления дают один вклад."""
    by_dir = {}
    for o in obs:
        p = dirw[o["direction"]] * trust(o["reliability"], o["credibility"])
        by_dir[o["direction"]] = max(by_dir.get(o["direction"], 0.0), p)
    prod = 1.0
    for p in by_dir.values():
        prod *= (1.0 - p)
    return 1.0 - prod, by_dir

def interest(values, weights):
    """Интерес(T) = S a_k(T) v_k / S a_k(T) по наблюдённым признакам.
    Непронаблюдённый признак исключается, веса остальных перенормируются."""
    num = sum(weights[k] * v for k, v in values.items() if k in weights)
    den = sum(weights[k] for k in values if k in weights)
    return (num/den if den else 0.0), den

def applicability(attack, covered, actor, min_groups=5):
    """Применимость(T) = S f(k,T) по покрытым / S f(k,T) по всем техникам типа."""
    parent = {}
    for tid, t in attack["techniques"].items():
        base = tid.split(".")[0]                      # T1566.001 -> T1566
        f = t["frequency"].get(actor, 0.0)
        parent[base] = max(parent.get(base, 0.0), f)  # агрегация семейства
    denom = sum(parent.values())
    numer = sum(v for k, v in parent.items() if k in covered)
    return (numer/denom if denom else 0.0), numer, denom, parent
