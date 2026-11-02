"""Обезличивание набора данных.

Что заменяется: названия, ИНН, домены, имена узлов, адреса, суммы выручки.
Что сохраняется: порты и службы, политики, имена автономных систем и
операторов (они относятся к поставщику, а не к объекту), все количества,
состояния наблюдения и результаты предикатов.

Выручка заменяется значениями, которые держат порядок: перцентиль зависит
только от порядка, поэтому все расчётные величины остаются теми же, а точные
суммы перестают быть поисковым запросом.

Запуск:  python anonymize.py --out data_demo
Прогон:  TARGETMAP_DATA=data_demo python full_run.py
"""
import argparse, json, pathlib, re, shutil

LETTERS = "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЭЮЯ"

# Общеизвестная инфраструктура не заменяется: публичные разрешители DNS — это
# инструмент сбора, а не адреса объекта. Замена здесь скрыла бы от читателя,
# чем собраны данные, и при этом ничего не защитила.
PUBLIC_INFRA = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "9.9.9.9", "208.67.222.222", "77.88.8.8"}

# Поля, которые вырезаются целиком. Оператор сканера возвращает тела ответов и
# заголовки страниц; ни один предикат их не читает, а содержат они живой текст
# сайта организации — название, телефоны, иногда фамилии сотрудников. Для
# публикуемого набора это и лишний вес, и лишние сведения о людях.
DROP = ("body", "html_title", "title", "favicon", "_decoded_body",
        "response_body", "html")
# Без \b слева: адрес встречается внутри URL (…%2f198.51.100.7%2f), и граница
# слова между буквой и цифрой не возникает.
# Без \b слева: адрес встречается внутри URL (…%2f203.0.113.1%2f). Справа
# допускается точка: автоимена вида 203.0.113.1.sslip.io содержат адрес целиком.
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
# Автоимена панелей хостинга записывают адрес дефисами:
# 3c5dd18384.91-107-124-188.ispmanager.name
IP_DASH_RE = re.compile(r"(?<![\d-])(?:\d{1,3}-){3}\d{1,3}(?![\d-])")


class Mapper:
    """Устойчивые замены: один и тот же вход всегда даёт один и тот же выход."""

    def __init__(self):
        self.ip, self.dom, self.brand, self.inn, self.rev = {}, {}, {}, {}, {}
        self.twin, self.label = {}, {}

    def twin_of(self, v, pseudo):
        """Домен-двойник повторяет имя объекта по построению, поэтому его
        тоже надо заменить. Нумерация устойчивая, порядок сохраняется."""
        if v not in self.twin:
            self.twin[v] = f"twin-{len(self.twin) + 1}.{pseudo}"
        return self.twin[v]

    def ip_of(self, v):
        # 203.0.113.0/24 — диапазон RFC 5737, отведённый под документацию.
        if v in PUBLIC_INFRA:
            return v
        if v not in self.ip:
            self.ip[v] = f"203.0.113.{len(self.ip) + 1}"
        return self.ip[v]

    def dom_of(self, v):
        if v not in self.dom:
            self.dom[v] = f"obj-{len(self.dom) + 1}.example"
        return self.dom[v]

    def brand_of(self, v):
        if v not in self.brand:
            i = len(self.brand)
            self.brand[v] = f"Объект {LETTERS[i]}" if i < len(LETTERS) else f"Объект {i+1}"
        return self.brand[v]

    def inn_of(self, v):
        if v not in self.inn:
            self.inn[v] = f"{7700000000 + len(self.inn) + 1}"
        return self.inn[v]

    def host(self, name, domains):
        """Имя узла. Метка сохраняется (lk, vpn, mail, dev несут смысл),
        доменная часть заменяется."""
        low = (name or "").lower().rstrip(".")
        for d in sorted(domains, key=len, reverse=True):
            if low == d or low.endswith("." + d):
                label = low[: -len(d) - 1] if low != d else ""
                nd = self.dom_of(d)
                return f"{label}.{nd}" if label else nd
       
        parts = low.split(".")
        if len(parts) > 2:
            head = parts[0]
            for d in domains:
                if head and head in d.replace(".", ""):
                    return ".".join(["obj"] + parts[1:])
        return low

    def text(self, s, domains):
        """Замена внутри произвольной строки: адреса, имена узлов, двойники
        и отдельно стоящая метка имени объекта."""
        if not isinstance(s, str):
            return s
        out = IP_RE.sub(lambda m: self.ip_of(m.group(0)), s)
        out = IP_DASH_RE.sub(
            lambda m: self.ip_of(m.group(0).replace("-", ".")).replace(".", "-"), out)
        for d in sorted(domains, key=len, reverse=True):
            out = re.sub(r"\b([\w-]+\.)*" + re.escape(d) + r"\b",
                         lambda m: self.host(m.group(0), domains), out)
        # Домены-двойники: метка объекта должна стоять во втором уровне имени,
        # то есть в регистрируемой части. Проверка по любой метке была бы
        # слишком широкой и захватывала бы поддомены на доменах поставщиков
        # вида <объект>.<поставщик>.ru, а это другое наблюдение.
        for base, pseudo in self.label.items():
            # Привязка к концу имени обязательна: без неё совпадает префикс
            # (<объект>.<поставщик> в <объект>.<поставщик>.ru), и поддомен
            # на домене поставщика ошибочно принимается за двойника.
            out = re.sub(r"\b([\w-]*" + re.escape(base) +
                         r"[\w-]*)\.([a-zA-Z]{2,})(?![\w.-])",
                         lambda m, p=pseudo: self.twin_of(m.group(0), p), out)
            # Поддомен, названный по объекту, на домене поставщика: заменяется
            # только метка, домен поставщика сохраняется — это другое
            # наблюдение, и оно должно остаться видимым.
            # Любое число меток после: имена арендаторов у почтовых служб
            # длиннее (doctru-com.mail.protection.outlook.com).
            out = re.sub(r"\b[\w-]*" + re.escape(base) +
                         r"[\w-]*((?:\.[\w-]+)+\.[a-zA-Z]{2,}\.?)(?![\w-])",
                         lambda m, p=pseudo: p.split(".")[0] + m.group(1), out)
            # Метка без домена: она стоит в диагностике различимости.
            out = re.sub(r"\b" + re.escape(base) + r"\b", pseudo.split(".")[0], out)
        for b, nb in self.brand.items():
            out = out.replace(b, nb)
        for i, ni in self.inn.items():
            out = out.replace(i, ni)
        return out

    def walk(self, node, domains):
        """Рекурсивная замена по всему дереву JSON, включая ключи.
        Поля из DROP не переносятся."""
        if isinstance(node, dict):
            return {self.text(k, domains): self.walk(v, domains)
                    for k, v in node.items() if k not in DROP}
        if isinstance(node, list):
            return [self.walk(v, domains) for v in node]
        return self.text(node, domains)


def run(src="data", out="data_demo"):
    src, out = pathlib.Path(src), pathlib.Path(out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    m = Mapper()

    objs = json.load(open(src / "objects.json", encoding="utf-8"))
    ref = json.load(open(src / "reference.json", encoding="utf-8"))
    manual = json.load(open(src / "manual.json", encoding="utf-8"))

    # Порядок замен задаёт порядок имён: сначала объекты оценки, затем референс.
    # Сначала основные домены, затем прежние написания: иначе нумерация
    # объектов идёт с пропусками.
    for o in objs["objects"]:
        m.brand_of(o["brand"]); m.inn_of(o["inn"]); m.dom_of(o["domain"])
    for o in objs["objects"]:
        for a in o.get("aliases") or []:
            m.dom_of(a)
    for r in ref["reference"]:
        m.brand_of(r["brand"]); m.inn_of(r["inn"])
    m.brand_of(ref["external"]["brand"]); m.inn_of(ref["external"]["inn"])
    domains = sorted(m.dom.keys(), key=len, reverse=True)
    # Метки имён объектов: нужны для замены доменов-двойников и диагностики.
    for d in domains:
        m.label[d.split(".")[0]] = m.dom[d]

    # Выручка: замена с сохранением порядка. Перцентиль зависит только от
    # порядка, поэтому все расчётные значения остаются прежними.
    all_rev = sorted({r["revenue"] for r in ref["reference"]} |
                     {o["revenue"] for o in objs["objects"]} |
                     {ref["external"]["revenue"]})
    m.rev = {v: (i + 1) * 100_000_000 for i, v in enumerate(all_rev)}

    # --- перечень объектов и признаки ОМС, запечённые вместо реестров
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import oms
    fed, reg = oms.federal(), oms.regional()
    baked = {}
    for o in objs["objects"]:
        recs = oms.features_for(o["inn"], fed, reg)
        baked[m.inn_of(o["inn"])] = m.walk(recs, domains)
        o["brand"] = m.brand_of(o["brand"])
        o["inn"] = m.inn_of(o["inn"])
        o["key"] = m.dom_of(o["key"]) if o["key"] in m.dom else m.dom_of(o["domain"])
        o["domain"] = m.dom_of(o["domain"])
        o["aliases"] = [m.dom_of(a) for a in (o.get("aliases") or [])]
        o["revenue"] = m.rev[o["revenue"]]
    objs["_note"] += (" Набор обезличен: названия, ИНН, домены, имена узлов, "
                      "адреса и суммы заменены. Порядок величин сохранён.")
    json.dump(objs, open(out / "objects.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    for r in ref["reference"]:
        r["brand"] = m.brand_of(r["brand"]); r["inn"] = m.inn_of(r["inn"])
        r["revenue"] = m.rev[r["revenue"]]
    e = ref["external"]
    e["brand"] = m.brand_of(e["brand"]); e["inn"] = m.inn_of(e["inn"])
    e["revenue"] = m.rev[e["revenue"]]
    json.dump(ref, open(out / "reference.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    manual = m.walk(manual, domains)
    manual["objects"] = {m.dom.get(k, k): v for k, v in (manual.get("objects") or {}).items()}
    manual["observations"] = {m.dom.get(k, k): v
                              for k, v in (manual.get("observations") or {}).items()}
    manual["own_asns"] = {m.dom.get(k, k): v for k, v in (manual.get("own_asns") or {}).items()}
    manual["oms_baked"] = baked
    json.dump(manual, open(out / "manual.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    # --- снимки
    n = 0
    for p in sorted((src / "raw").rglob("*.json")):
        rel = p.relative_to(src / "raw")
        obj = rel.parts[0]
        new_obj = m.dom.get(obj, obj)
        dst = out / "raw" / new_obj / pathlib.Path(*rel.parts[1:])
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = m.walk(json.load(open(p, encoding="utf-8")), domains)
        json.dump(data, open(dst, "w", encoding="utf-8"), ensure_ascii=False)
        n += 1

    print(f"обезличено: {len(m.dom)} доменов, {len(m.brand)} названий, "
          f"{len(m.ip)} адресов, {n} снимков -> {out}/")
    # Проверяются и выходной набор, и исходники пакета: обозначение, попавшее
    # в комментарий или в умолчание аргумента, публикуется ровно так же, как
    # попавшее в снимок. Первая версия проверки смотрела только набор данных
    # и пропускала код.
    leaks = check([out, pathlib.Path(__file__).resolve().parent], m, src=src)
    if leaks:
        print("\nПРОВЕРКА НЕ ПРОЙДЕНА: в обезличенном наборе остались исходные "
              "обозначения. Публиковать нельзя.")
        for what, files in sorted(leaks.items()):
            print(f"  {what} -> {', '.join(files[:3])}")
        raise SystemExit(1)
    print(f"проверка пройдена: {len(m.brand) + len(m.inn) + len(m.dom) + len(m.ip)} "
          f"обозначений, ни одно не встречается в выдаче")
    print("соответствие в репозиторий НЕ кладётся: оно остаётся только локально")
    return m


# Что не просматривается: рабочий набор данных, служебные каталоги и сам обезличиватель,
# в котором перечень замен присутствует по устройству.
SKIP_DIRS = {".git", "__pycache__", "exports"}

def check(roots, m, src=None):
    """Поиск исходных обозначений в обезличенном наборе И в исходниках.

    Проверка обязательна и выполняется автоматически: ошибка в замене не видна
    глазом, а цена её — публикация тех самых сведений, ради сокрытия которых
    набор и делается. Ищутся названия, ИНН, домены, метки имён, адреса в точках
    и в дефисах.
    """
    roots = [pathlib.Path(r) for r in (roots if isinstance(roots, (list, tuple)) else [roots])]
    src = pathlib.Path(src).resolve() if src else None
    needles = (set(m.brand) | set(m.inn) | set(m.dom) | set(m.ip)) - PUBLIC_INFRA
    needles |= {d.split(".")[0] for d in m.dom}
    needles |= {ip.replace(".", "-") for ip in m.ip}
    needles = {x for x in needles if x and len(str(x)) >= 4}
    leaks = {}
    seen = set()
    for root in roots:
        for p in root.rglob("*"):
            if not p.is_file() or p in seen:
                continue
            seen.add(p)
            rp = p.resolve()
            if src and (rp == src or src in rp.parents):
                continue                      # рабочий набор не просматривается
            if rp.name == "anonymize.py":
                continue                      # перечень замен здесь по устройству
            if SKIP_DIRS & set(p.parts):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for x in needles:
                if str(x) in text:
                    leaks.setdefault(str(x), []).append(str(p))
    return leaks


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Собрать обезличенный набор данных")
    ap.add_argument("--src", default="data")
    ap.add_argument("--out", default="data_demo")
    run(ap.parse_args().src, ap.parse_args().out)
