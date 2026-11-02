"""Общее для сборщиков: журнал шагов и запись снимка.

Снимок — единица хранения сырья. Пишется всегда, даже если источник недоступен:
снимок с пустыми данными и журналом отказа — это зафиксированное «не проверено»,
без которого полноту наблюдения посчитать нельзя."""
import json, datetime, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from paths import RAW

class Log:
    """Журнал шагов сборщика. Уровень fail не прерывает работу: сборщик обязан
    дописать снимок, иначе отказ источника потеряется и превратится
    в «не обнаружено» на следующем шаге."""
    def __init__(self): self.items = []
    def step(self, m): self._add("step", m)
    def ok(self, m):   self._add("ok", m)
    def warn(self, m): self._add("warn", m)
    def fail(self, m): self._add("fail", m)
    def url(self, m):  self._add("url", m)
    def _add(self, lvl, m):
        self.items.append({"level": lvl, "message": m})
        print(f"    [{lvl}] {m}")
    def summary(self):
        s = {}
        for i in self.items: s[i["level"]] = s.get(i["level"], 0) + 1
        return s

def save(collector, obj, data, log, day=None):
    """Снимок кладётся в data/raw/<объект>/<дата>/<сборщик>.json.
    Дата в пути, а не в имени: повторный прогон другого дня не перезаписывает старый,
    и временной ряд для производной обстановки накапливается сам."""
    day = day or datetime.date.today().isoformat()
    p = RAW / obj / day / f"{collector}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "collector": collector, "object": obj,
        "collected_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "observed_at": day,
        "log": log.items, "log_summary": log.summary(), "data": data,
    }, ensure_ascii=False, indent=1))
    print(f"    снимок: {p}")
    return p
