"""Прогон одного объекта. Шаги идут в порядке зависимостей по данным.

Шаг 8 (обстановка сегмента) в этот прогон не входит."""
import argparse, sys, datetime, json
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from objects import BY_KEY, EVALUATED
from paths import snapshot

PLAN = [
 ("crtsh",       "внешние имена из журналов прозрачности", "собственного признака не даёт"),
 ("dns",         "DNS: адреса, почтовый канал, разрешимость имён", "ключевой шаг: адреса дают дедупликацию узлов"),
 ("dnstwist",    "домены-двойники", "цепочка предикатов: различимость, регистрация, почта"),
 ("fingerprint", "фингерпринт главной страницы", "один запрос, обход сайта не выполняется"),
 ("zakupki",     "государственные закупки по ИНН", "ручной ввод, подтверждённый ноль"),
 ("censys",      "службы на подтверждённых узлах", "требует согласия и токена, идёт последним"),
]

# Внешние инструменты проверяются один раз на старте.
REQUIRED = {
    "dnstwist": ("домены-двойники", "pip install dnstwist"),
    "dig":      ("DNS через публичные разрешители", "входит в bind-utils / dnsutils; "
                                                    "в macOS есть из коробки"),
}

def preflight(steps):
    """Проверка окружения. Возвращает список недостающего, пустой — всё на месте."""
    import shutil
    need = {"dnstwist": "dnstwist", "dns": "dig"}      # шаг -> инструмент
    missing = []
    for step, _, _ in steps:
        tool = need.get(step)
        if tool and not shutil.which(tool):
            what, how = REQUIRED[tool]
            missing.append((tool, what, how))
    return missing

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--object", required=True, help="ключ объекта из objects.py")
    ap.add_argument("--only", help="выполнить только один шаг")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--skip-censys", action="store_true")
    a = ap.parse_args()
    o = BY_KEY.get(a.object)
    if not o:
        print("Известные объекты:"); [print("  ", x["key"], "-", x["brand"]) for x in EVALUATED]
        return 1
    day = datetime.date.today().isoformat()
    print(f"\nОБЪЕКТ: {o['brand']}, ИНН {o['inn']}, {o['domain']}")
    print(f"Роль в выборке: {o['role']}")
    # Фильтрация ДО печати счётчика, иначе расхождение выглядит как 6 шаг.
    steps = [s for s in PLAN if (not a.only or s[0] == a.only)]
    if a.skip_censys: steps = [s for s in steps if s[0] != "censys"]
    skipped = [s[0] for s in PLAN if s not in steps]
    print(f"Прогон {day}. Этапов: {len(steps)} из {len(PLAN)}.")
    if skipped: print(f"Пропущено по ключам запуска: {', '.join(skipped)}")

    missing = preflight(steps)
    if missing and not a.dry_run:
        print()
        print("ПРОГОН НЕ НАЧАТ: не хватает внешних инструментов.")
        for tool, what, how in missing:
            print(f"  {tool} — нужен для шага «{what}»")
            print(f"      установить: {how}")
        print()
        print("Это ошибка окружения, а не состояние данных: продолжать нельзя, иначе")
        print("группа признаков окажется непронаблюдённой по всей выборке.")
        print("Чтобы прогнать остальные шаги без него, добавьте --only <шаг>.")
        return 2
    print()
    for i, (name, title, note) in enumerate(steps, 1):
        print(f"[{i}/{len(steps)}] {title}")
        print(f"        {note}")
        if a.dry_run:
            print(f"        --dry-run: шаг не выполняется")
            continue
        try:
            if name == "crtsh":
                from collect import crtsh; crtsh.collect(o["domain"], o["key"], day)
            elif name == "dns":
                hosts = None
                try:
                    hosts = json.load(open(snapshot(o["key"], day, "crtsh")))["data"]["hosts"]
                    print(f"        имён из crt.sh: {len(hosts)}")
                except Exception:
                    print(f"        снимка crt.sh за сегодня нет, проверяется только домен")
                from collect import dns_collect; dns_collect.collect(o["domain"], hosts, o["key"], day)
            elif name == "dnstwist":
                from collect import dnstwist; dnstwist.collect(o["domain"], o["key"], day)
            elif name == "fingerprint":
                from collect import fingerprint; fingerprint.collect(o["domain"], o["key"], day)
            elif name == "zakupki":
                from collect import zakupki; zakupki.collect(o["key"], o["inn"], [], day)
            elif name == "censys":
                from collect import censys; censys.collect(o["key"], False, day)
        except Exception as e:
            # Отказ шага не прерывает прогон: снимок с состоянием «не проверено»
            # уже записан сборщиком, а полнота наблюдения это учтёт.
            print(f"        [fail] шаг не выполнен: {type(e).__name__}: {e}")
        print()
    print("Готово. Снимки в data/raw/%s/%s/" % (o["key"], day))
    return 0

if __name__ == "__main__":
    sys.exit(main())
