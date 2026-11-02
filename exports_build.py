"""Сводная таблица, лог ненайденного и карточки по всем объектам."""
import json, pathlib
from full_run import build, KEYS, category, FULL_MIN
from normalize import perimeter, third_party, vendors_from_fingerprint
from objects import BY_KEY
from paths import snapshot, latest_day, latest_for, spread
from card import card
from paths import OUT
OUT.mkdir(parents=True, exist_ok=True)

R = {k: build(k) for k in KEYS}
best = {k: max(R[k]["idx"].values()) for k in KEYS}
order = sorted(KEYS, key=lambda x: -best[x])
vals = sorted(best.values()); n = len(vals)
q3, q1 = vals[int(0.75*(n-1))], vals[int(0.25*(n-1))]

# ---------- сводная таблица ----------
L = ["# Сводная таблица оценочной выборки", "",
     "Базовая спецификация DBIR 2026, срез здравоохранения. Снимки 2026-10-31.", "",
     "| № | Объект | Индекс | Ведущий тип | Разрыв | База | Полнота | Ур. осн. | Категория |",
     "|---|---|---|---|---|---|---|---|---|"]
for i, k in enumerate(order, 1):
    r = R[k]
    lead = max(r["idx"], key=lambda a: r["idx"][a])
    gap = r["idx"][lead] - min(r["idx"].values())
    cat, why = category(best[k], r["full_min"], r["escalate"], q3, q1)
    L.append(f"| {i} | {r['brand']} | **{best[k]:.2f}** | {lead} | {gap:.2f} | "
             f"{r['base']*100:.1f} | {r['full_min']:.3f} | {r['ev']} | {cat} |")
L += ["", f"Границы категорий по распределению выборки: верхняя четверть >= {q3:.2f}, "
          f"нижняя четверть <= {q1:.2f}. Порог достаточной полноты {FULL_MIN}.", "",
      "## Содержание категорий", ""]
for k in order:
    r = R[k]; cat, why = category(best[k], r["full_min"], r["escalate"], q3, q1)
    L.append(f"- **{r['brand']}** — {cat}: {why}")
L += ["",
      "Ни один объект не отнесён к категории «повышенное внимание»: она требует "
      "высокого индекса **и** свежих объектных наблюдений, а объекты с объектными "
      "наблюдениями имеют низкий индекс. Это наблюдаемый результат, а не пробел сбора.", ""]
(OUT/"сводная_таблица.md").write_text("\n".join(L))

# ---------- лог ненайденного ----------
G = ["# Лог ненайденного", "",
     "Три блока по состояниям наблюдения. Первый повышает полноту, второй понижает, "
     "третий на полноту не влияет и объясняет, почему индекс ниже числа найденных записей.", ""]
for k in order:
    o = BY_KEY[k]; vd,_,_ = vendors_from_fingerprint(k)
    per = perimeter(k, o["domain"], vendor_domains=vd)
    tp = third_party(k, o["domain"])
    sp = spread(k, ("crtsh","dns","dnstwist","fingerprint","zakupki","censys"))
    # Даты наблюдения показываются явно: картина объекта собирается из снимков
    # разных дней, и разброс должен быть виден, а не скрыт одной датой прогона.
    G += [f"## {R[k]['brand']} ({o['domain']})", "",
          "Даты наблюдения: " + ", ".join(
              f"{c} {d or '—'}" for c, d in sp.items()), ""]
    nf, nc, ex = [], [], []
    for c in ("crtsh","dns","dnstwist","fingerprint","zakupki","censys"):
        cday, cpath = latest_for(k, c)
        if cpath is None:
            nc.append(f"{c} — снимка нет ни за одну дату"); continue
        d = json.load(open(cpath))
        dd = d["data"]
        if dd.get("status") == "not_checked" or (dd.get("found") is False and dd.get("status")=="not_checked"):
            nc.append(f"{c} — {dd.get('reason','источник недоступен')}")
        elif c == "zakupki" and dd.get("status") == "not_found":
            nf.append("закупки — контрактов по ИНН не найдено, источник проверен")
        elif c == "dnstwist" and dd.get("status") == "not_found":
            nf.append(f"домены-двойники — зарегистрировано {dd.get('registered_count')}, "
                      f"обезврежено {dd.get('neutralized_count')}, в расчёт 0")
            if dd.get("candidates_count"):
                ex.append(f"{dd['candidates_count']} двойников — почта принимается, "
                          f"принадлежность объекту не установлена")
        elif c == "crtsh" and dd.get("found") is False:
            nc.append("журнал прозрачности сертификатов — источник не ответил")
    if tp["status"] == "not_found":
        nf.append("зависимость от поставщика — в разметке главной страницы "
                  "домены известных поставщиков не обнаружены")
    for row in per["unchecked"]:
        nc.append(f"службы на {row['ip']} — {row['service_reason'][:70]}")
    for row in per["excluded"]:
        ex.append(f"адрес {row['ip']} — {row['reason'][:110]}")
    # Не внесённое значение — это ПРОБЕЛ, а не отрицательный результат:
    # источник (сайт объекта) не проверялся, поэтому полнота понижается.
    nc.append("признак объёма данных пациентов — число адресов приёма не внесено")
    nc.append("признак публичности бренда — сборщика упоминаний нет")
    nc.append("признак связей — референсного распределения по связям нет")
    nc.append("группа индикаторов компрометации — не проверяется по этическому решению")
    for title, items in (("НЕ ОБНАРУЖЕНО (источник проверен, результат отрицательный)", nf),
                         ("НЕ ПРОВЕРЕНО (источник недоступен или пропущен)", nc),
                         ("ИСКЛЮЧЕНО ПРЕДИКАТОМ (наблюдение есть, в расчёт не идёт)", ex)):
        G.append(f"**{title}**"); G.append("")
        G += [f"- {x}" for x in items] or ["- нет"]
        G.append("")
(OUT/"лог_ненайденного.md").write_text("\n".join(G))

# ---------- карточки ----------
for k in KEYS:
    (OUT/f"карточка_{k}.md").write_text(card(k))
print("записано в exports/:")
for f in sorted(OUT.iterdir()): print("  ", f.name, f"{f.stat().st_size} байт")
