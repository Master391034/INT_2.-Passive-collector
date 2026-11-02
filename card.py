"""Карточка объекта по спецификации методологии.

Карточка — не пересказ методологии. Тот, кто ей пользуется, знает, что несёт
глубина зависимости, почему непронаблюдённое исключается с перенормировкой и
откуда взяты веса. Поэтому здесь только то, что относится к ЭТОМУ объекту:
значения, их источники, состояния наблюдения и вопросы к проверке.

Таблиц нет сознательно: сводные таблицы по выборке приводятся один раз в
демонстрации, и повторять их по каждому объекту значило бы дублировать уже
показанное.
"""
import json, sys
from full_run import (build, KEYS, FON, category, quartiles, ADDRESSES)
from normalize import perimeter, third_party, vendors_from_fingerprint
from objects import BY_KEY
from calc import SPEC_BASE, group_weights
from paths import DATA, spread
from inputs import load

MANUAL = load("manual.json", default={}, quiet=True) or {}
RU = {"criminal": "киберпреступники", "apt": "APT"}

def _svc(s):
    """Имя службы. Оператор отдаёт UNKNOWN, когда протокол не распознан, —
    это «не определена», а не название службы."""
    n = (s.get("service_name") or s.get("protocol") or "").strip()
    return "не определена" if not n or n.upper() == "UNKNOWN" else n

def plural(n, one, few, many):
    """Согласование числительного: 1 адрес, 2 адреса, 5 адресов."""
    n = abs(n) % 100
    if 11 <= n <= 14: return many
    n %= 10
    return one if n == 1 else few if 2 <= n <= 4 else many

def _dates(key):
    """Даты наблюдения. Совпадающие сворачиваются в одну: разброс важен,
    а его отсутствие перечислением шести одинаковых дат не показывают."""
    sp = spread(key)
    got = {c: d for c, d in sp.items() if d}
    missing = [c for c, d in sp.items() if not d]
    uniq = sorted(set(got.values()))
    if len(uniq) == 1:
        s = f"все источники — {uniq[0]}"
    else:
        s = ", ".join(f"{c} {d}" for c, d in got.items())
    if missing:
        s += "; не проверено: " + ", ".join(missing)
    return s

def card(key):
    o = BY_KEY[key]; r = build(key)
    vd, _, _ = vendors_from_fingerprint(key)
    per = perimeter(key, o["domain"], vendor_domains=vd)
    grw = group_weights(SPEC_BASE)
    q3, q1 = quartiles()
    lead = max(r["idx"], key=lambda a: r["idx"][a])
    second = min(r["idx"], key=lambda a: r["idx"][a])
    cat, why = category(r["idx"][lead], r["full_min"], r["escalate"], q3, q1)
    L = []; A = L.append

    A(f"# {o['brand']} — {o['domain']}, ИНН {o['inn']}")
    A("")

    # ---- вердикт
    A(f"**Приоритет {r['idx'][lead]:.2f}**, ведущая угроза — {RU[lead]}, "
      f"разрыв со следующим типом {r['idx'][lead] - r['idx'][second]:.2f}. "
      f"Индекс хактивистов не ранжируется.")
    A("")
    A(f"**Полнота:** по признакам интереса {r['full'][lead]:.3f} ({RU[lead]}) и "
      f"{r['full'][second]:.3f} ({RU[second]}), по весу пронаблюдённых групп "
      f"достижимости {r['full_reach']:.3f}, связывающая **{r['full_min']:.3f}**.")
    A("")
    A(f"**Уровень оснований {r['ev']}** — {r['obs_why']}." +
      (" Сработало правило эскалации: ручная проверка независимо от индекса."
       if r["escalate"] else ""))
    A("")
    A(f"**Категория: {cat}** — {why}.")
    A("")
    A(f"Даты наблюдения: {_dates(key)}.")
    A("")

    # ---- интерес
    A("## Интерес")
    A("")
    NAMES = {"INT.PAY": "платёжеспособность", "INT.DATA": "объём данных пациентов",
             "INT.GOV": "участие в госпрограммах", "INT.CRIT": "критичность услуг"}
    src = {"INT.PAY": "выручка по строке 2110 ГИР БО, перцентиль референса",
           "INT.DATA": f"{ADDRESSES.get(key)} "
                       f"{plural(ADDRESSES.get(key) or 0, 'подтверждённый адрес', 'подтверждённых адреса', 'подтверждённых адресов')}"
                       f" приёма по юрлицу, перцентиль референса",
           "INT.GOV": (r["oms"] or "в федеральном реестре ОМС отсутствует"),
           "INT.CRIT": r["crit_src"]}
    for k, v in r["vals"].items():
        A(f"- {NAMES[k]} **{v:.3f}** — {src[k]}")
    A("- не пронаблюдены: публичность бренда (сборщика упоминаний нет), "
      "связи с организациями (референсного распределения нет)")
    A("")

    # ---- достижимость
    A("## Достижимость")
    A("")
    own = [x for x in per["own"] if "asset" in x]
    nall = len(own) + len(per["unchecked"]) + len(per["supplier"]) + len(per["excluded"])
    def own_w(n): return plural(n, "свой", "своих", "своих")
    parts = [f"{len(own)} {own_w(len(own))} со службами"] if own else []
    if per["unchecked"]:
        n = len(per["unchecked"]); parts.append(f"{n} {own_w(n)} без ответа оператора")
    if per["supplier"]:
        parts.append(f"{len(per['supplier'])} на инфраструктуре поставщика")
    if per["excluded"]:
        n = len(per["excluded"])
        parts.append(f"{n} {plural(n, 'исключён', 'исключены', 'исключено')} привязкой")
    A(f"- адресов по именам объекта {nall}: " + ", ".join(parts) +
      f". P(группа 2) **{r['P2']:.4f}**")
    for x in own:
        A(f"  - `{x['ip']}` — службы: " +
          ", ".join(f"{s.get('port')}/{_svc(s)}" for s in x["services"]))
    for x in per["supplier"]:
        A(f"  - `{x['ip']}` — {', '.join(x['own_names'][:2])}: {x['reason']}")
    mail = "; ".join(f"{m['feature'].split('.')[-1]} {m.get('value_num')}"
                     f" ({m.get('note') or m.get('reason','')})" for m in per["mail"])
    A(f"- почтовый канал: {mail}")
    if r["P3"] is None:
        A("- третья сторона: **не пронаблюдена** ни одним каналом, группа исключена "
          "с перенормировкой")
    else:
        d = [x for x in r["tp_detail"] if x.get("depth")]
        if d:
            A(f"- третья сторона **{r['P3']:.4f}** — " +
              "; ".join(f"глубина {x['depth']} ({x['kind']}), достоверность "
                        f"{x['credibility']}" for x in d))
            for x in d:
                A(f"  - {x['what']}")

        else:
            A("- третья сторона: проверено, не обнаружено")
    A(f"- покрытые техники: {', '.join(r['covered'])}")
    A(f"- база достижимости **{r['base']*100:.1f}**")
    A("")

    # ---- наблюдения вне индекса
    obs = (MANUAL.get("observations") or {}).get(key) or []
    if obs:
        A("## Наблюдения об объекте вне индекса")
        A("")
        for x in obs:
            A(f"- **{x['what']}** ({x['source']}, {x['reliability']}/{x['credibility']}). "
              f"{x['evidence']}. Следствие: {x['consequence']}")
        A("")

    # ---- границы
    A("## Границы оценки")
    A("")
    A(f"- индикаторы компрометации не наблюдались по этическому решению, вес "
      f"исключённой группы {grw[1]:.4f}: оценка в этой части — нижняя граница")
    if per["unchecked"]:
        A(f"- служб не возвращено по {len(per['unchecked'])} адресам (тариф оператора "
          f"отдаёт базовые протоколы): вклад эксплуатации — нижняя граница")
    A("- версии программ оператором не возвращаются, ветка измеренной вероятности "
      "эксплуатации не включается")
    if r.get("tp_status") == "not_found" and (r.get("infra") or {}).get("status") == "confirmed":
        A("- отрицательный результат по глубине 1 установлен узким каналом: "
          "поставщик обнаруживается только если называет себя в разметке или "
          "занимает адрес, связываемый оператором с его доменом")
    A("")

    # ---- развилки
    A("## Развилки")
    A("")
    if per["supplier"]:
        A("- обрабатывает ли поставщик персональные данные пациентов в контуре, "
          "где размещено наблюдаемое имя объекта")
    if per["unchecked"]:
        A("- какие службы на адресах, по которым оператор не вернул данные")
    RA = ("vpn", "rdp", "remote", "citrix", "anyconnect")
    named = sorted({f"{nm} -> {x['ip']}" for x in per["unchecked"]
                    for nm in x["own_names"]
                    if any(nm.split(".")[0].lower().startswith(w) for w in RA)})
    if named and "T1133" not in r["covered"]:
        A(f"- узлы названы по назначению удалённого доступа ({', '.join(named)}), "
          "службы доступа по ним не наблюдаются: T1133 не засчитана")
    A("- принадлежность зарегистрированных доменов-двойников")
    if r["crit_src"] == "аналитик":
        A("- критичность услуг внесена аналитиком: достоверность повышают сведения "
          "об условиях оказания помощи по этому юридическому лицу, а не факт "
          "участия в ОМС")
    return "\n".join(L)

if __name__ == "__main__":
    print(card(sys.argv[1] if len(sys.argv) > 1 else "doct.ru"))
