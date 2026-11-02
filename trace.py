"""Пошаговая трассировка расчёта по одному объекту.

Трассировка показывает ход вычисления, а не воспроизводит его.
"""
import argparse, json
from objects import BY_KEY
from reference import REV, ADDR, percentile
from calc import (SPEC_BASE, direction_weights, group_weights, trust,
                  interest, applicability)
# group_value берётся из normalize: в calc осталась ранняя версия со взятием
# максимума. Разбор обязан вызывать те же функции, что прогон.
from normalize import perimeter, third_party, vendors_from_fingerprint, group_value
from full_run import (build, FON, COVERED, attack, REVENUE,
                      OBJECT_OBS, ESC, MANUAL, ADDRESSES, oms_features)
from paths import spread
import oms

ap = argparse.ArgumentParser(description="Разбор расчёта по сохранённым снимкам; сеть не используется")
# Умолчание - первый объект перечня, а не зашитое имя: имя реальной
# организации в коде выдавало бы состав оценочной выборки.
from objects import EVALUATED
ap.add_argument("--object", default=EVALUATED[0]["key"])
ap.add_argument("--day", help="дата снимка для воспроизведения; по умолчанию каждый "
                              "сборщик берётся по своей свежей дате")
a = ap.parse_args()
KEY = a.object
o = BY_KEY[KEY]
W = print

dirw, grw = direction_weights(SPEC_BASE), group_weights(SPEC_BASE)
vd, vend, fp_checked = vendors_from_fingerprint(KEY, a.day)
per = perimeter(KEY, o["domain"], a.day, vd)
tp = third_party(KEY, o["domain"], a.day)

W("=" * 78)
W(f"ОБЪЕКТ: {o['brand']}, ИНН {o['inn']}, {o['domain']}")
W(f"Роль в выборке: {o['role']}")
W("Даты наблюдения: " + ", ".join(f"{c} {d or 'не проверено'}"
                                 for c, d in spread(KEY).items()))
W("=" * 78)

# --------------------------------------------------------- ШАГ 1. ИНТЕРЕС
W("\n--- ШАГ 1. ФАКТОР ИНТЕРЕСА ---")
W("Оцениваем, чем объект притягателен сам по себе, независимо от того, как в него войти.")
omsf = {r["feature"]: r for r in oms_features(o["inn"])}
man = MANUAL.get(KEY, {})
crit = omsf.get("INT.CRIT", {}).get("value_num")
crit_src = "реестр ТРМО: " + str(omsf.get("INT.CRIT", {}).get("value_text", ""))
if crit is None:
    crit, crit_src = man.get("INT.CRIT"), "аналитик: " + str(man.get("basis", ""))
vals = {"INT.PAY": percentile(REVENUE[KEY], REV),
        "INT.DATA": percentile(ADDRESSES[KEY], ADDR) if ADDRESSES.get(KEY) else None,
        "INT.GOV": omsf.get("INT.GOV", {}).get("value_num"),
        "INT.CRIT": crit}
vals = {k: v for k, v in vals.items() if v is not None}
SRC = {"INT.PAY": f"выручка {REVENUE[KEY]/1e9:.2f} млрд, перцентиль по {len(REV)} юрлицам, A/1",
       "INT.DATA": f"{ADDRESSES.get(KEY)} подтверждённых адресов приёма по юрлицу, "
                   f"перцентиль по {len([v for v in ADDR if v is not None])} заполненным, A/2",
       "INT.GOV": "федеральный реестр ОМС: " + (omsf.get("INT.GOV", {}).get("value_text") or "отсутствует"),
       "INT.CRIT": crit_src}
for k, v in vals.items():
    W(f"  {k:<10} = {v:.4f}   {SRC[k]}")
for k in ("INT.PUB", "INT.LINK"):
    if k not in vals:
        why = {"INT.PUB": "сборщика упоминаний нет",
               "INT.LINK": "референсного распределения по связям нет"}[k]
        W(f"  {k:<10} — НЕ ПРОВЕРЕН ({why}) -> исключается с перенормировкой")
W("  Непронаблюдённый признак исключается, а не приравнивается к нулю: ноль — это")
W("  утверждение «признака нет», и делать его из пробела сбора нельзя.")
I, FULL = {}, {}
for actor in ("criminal", "apt", "hacktivist"):
    I[actor], FULL[actor] = interest(vals, SPEC_BASE["interest"][actor])
    W(f"  Интерес({actor:<10}) = {I[actor]:.4f} -> {I[actor]*100:5.1f}   "
      f"полнота интереса = {FULL[actor]:.4f}")
W("  Полноты различаются по типам: один и тот же непронаблюдённый признак весит")
W("  у типов по-разному, поэтому неполнота задевает их неодинаково.")

# ---------------------------------------------------- ШАГ 2. ДОСТИЖИМОСТЬ
W("\n--- ШАГ 2. ФАКТОР ДОСТИЖИМОСТИ ---")
W("Оцениваем, насколько объект доступен наблюдаемыми путями входа.")
W(f"  веса направлений: " + ", ".join(f"{k} {v:.4f}" for k, v in dirw.items()))
W(f"  веса групп:       " + ", ".join(f"гр.{k} {v:.4f}" for k, v in grw.items()))

W("\n  Слой 1. Привязка адресов: какие из найденных адресов принадлежат объекту.")
n_all = len(per["own"]) + len(per["excluded"]) + len(per["supplier"]) + len(per["unchecked"])
W(f"    всего адресов по именам объекта: {n_all}")
for row in per["own"]:
    if "asset" in row:
        W(f"      {row['ip']:<16} свой, служб {len(row['services'])}: "
          f"{', '.join(s.get('port', '?') and str(s['port']) for s in row['services'][:8])}")
for row in per["unchecked"]:
    W(f"      {row['ip']:<16} свой, службы НЕ ПРОВЕРЕНЫ — {row['service_reason'][:60]}")
for row in per["supplier"]:
    W(f"      {row['ip']:<16} ИНФРАСТРУКТУРА ПОСТАВЩИКА — {row['reason'][:60]}")
for row in per["excluded"]:
    W(f"      {row['ip']:<16} исключён — {row['reason'][:60]}")
W(f"    в активы направления «эксплуатация» ушло: "
  f"{len([r for r in per['own'] if 'asset' in r])}")
W("    Исключённый адрес — не консервативная погрешность, а неверная атрибуция:")
W("    службы чужой организации завышали бы оценку объекта.")

W("\n  Слой 2. Почтовый канал: решает политика, а не наличие записи.")
for m in per["mail"]:
    W(f"      {m['feature']:<16} = {m.get('value_num')} ({m['status']}) — "
      f"{(m.get('note') or m.get('reason') or '')[:70]}")

W("\n  Слой 3. Зависимость от третьей стороны, по наблюдаемой глубине доступа.")
W("  Глубину несёт достоверность производного утверждения «компрометация этой")
W("  стороны достигает объекта»: путь данных 1-2, путь трафика 3, путь")
W("  инфраструктуры 5. Дедупликация по владельцу, а не по автономной системе.")
_b0 = build(KEY)
for _d in _b0["tp_detail"]:
    if _d.get("depth"):
        W(f"      глубина {_d['depth']}, достоверность {_d['credibility']}: {_d['kind']}")
        W(f"          {_d['what'][:120]}")
    else:
        W(f"      {_d['kind']}: {_d['what'][:120]}")

W("\n  Свёртка. Внутри направления активы насыщаются к весу направления,")
W("  между направлениями берётся насыщающая свёртка.")
assets = {"exploit": [dict(r["asset"], value_num=1.0) for r in per["own"] if "asset" in r],
          "phishing": []}
mv = [m for m in per["mail"] if m["status"] == "confirmed" and m.get("value_num")]
if mv:
    b = max(mv, key=lambda m: m["value_num"])
    assets["phishing"] = [{"reliability": b["reliability"], "credibility": b["credibility"],
                           "value_num": b["value_num"]}]
    W(f"      по почте взят максимум внутри направления: {b['feature']} "
      f"= {b['value_num']} ({b['reliability']}/{b['credibility']}, "
      f"доверие {trust(b['reliability'], b['credibility']):.2f})")
P2, bd2 = group_value({k: dirw[k] for k in assets}, assets)
# bd2 — разбивка по направлениям: {направление: {p, saturation, assets}}
for k, v in bd2.items():
    W(f"      направление {k:<11} активов {v['assets']}  насыщение {v['saturation']:.4f}  "
      f"вклад {v['p']:.4f} (потолок — вес направления {dirw[k]:.4f})")
W(f"      P(группа 2) = 1 - " + " x ".join(f"(1-{v['p']:.4f})" for v in bd2.values()) +
  f" = {P2:.4f}")
# Группа 3 берётся из конвейера: каналов наблюдения зависимости стало больше
# одного, и дублировать их сведение здесь значило бы снова развести расчёты.
_b = build(KEY)
P3 = _b["P3"]
groups = {2: P2}
if P3 is not None:
    groups[3] = P3
    W(f"      P(группа 3) = {P3:.4f}" +
      ("" if P3 > 0 else " — источник проверен, зависимости не обнаружено"))
else:
    W(f"      группа 3 НЕ ПРОНАБЛЮДЕНА: исключается с перенормировкой")
W(f"      группа 1 (индикаторы компрометации) не пронаблюдена по этическому решению; "
  f"вес {grw[1]:.4f}")
den = sum(grw[g] for g in groups)
BASE = sum(grw[g] * v for g, v in groups.items()) / den
W(f"      База = (" + " + ".join(f"{grw[g]:.4f} x {v:.4f}" for g, v in groups.items()) +
  f") / {den:.4f} = {BASE:.4f} -> {BASE*100:.1f}")
full_reach = den / sum(grw.values())
W(f"      полнота по весу пронаблюдённых групп = {den:.4f} / {sum(grw.values()):.4f} "
  f"= {full_reach:.4f}")
W("      Перенормировка ПОВЫШАЕТ базу относительно наблюдённого нуля, поэтому её")
W("      всегда сопровождает полнота: иначе неудачный сбор выглядит достижимостью.")

# ----------------------------------------------------- ШАГ 3. ПРИМЕНИМОСТЬ
W("\n--- ШАГ 3. ПРИМЕНИМОСТЬ ПОВЕРХНОСТИ К ТИПАМ НАРУШИТЕЛЯ ---")
W("Одна и та же поверхность не одинаково применима разными нарушителями.")
# Набор покрытых техник свой у каждого объекта.
cov, cov_why = _b["covered"], _b["covered_why"]
W(f"  покрытые техники объекта: {', '.join(cov)}")
for t in cov:
    W(f"      {t}: {cov_why.get(t,'')[:110]}")
APP = {}
for actor in ("criminal", "apt", "hacktivist"):
    APP[actor], num, dn, _ = applicability(attack, set(cov), actor)
    W(f"  {actor:<10} числитель {num:.4f} / знаменатель {dn:.4f} = {APP[actor]:.4f}")
W("  Хактивисты: частоты не используются — размеченных профилей слишком мало,")
W("  числитель и знаменатель совпадают, и доля перестаёт быть измерением.")
REACH = {x: BASE * APP[x] for x in ("criminal", "apt")}
for x, r in REACH.items():
    W(f"  Достижимость({x:<8}) = {BASE:.4f} x {APP[x]:.4f} = {r:.4f} -> {r*100:5.1f}")

# ------------------------------------------------------- ШАГ 4. ОБСТАНОВКА
W("\n--- ШАГ 4. ФАКТОР ОБСТАНОВКИ ---")
W(f"  базовый уровень сегмента = {FON:.4f} -> {FON*100:.1f} (одинаков для всех типов)")
lvl, why = OBJECT_OBS.get(KEY, ("none", "объектных наблюдений не найдено"))
W(f"  объектные наблюдения: {why}")
W(f"  уровень оснований {ESC[lvl]}" +
  ("  -> правило эскалации: ручная проверка независимо от индекса" if ESC[lvl] >= 4 else ""))
W("  Числовой надбавки за объектное наблюдение нет: опубликованной частоты")
W("  повторной атаки по сегменту не найдено, а назначенный интервал был бы")
W("  соглашением без источника. Объектное наблюдение действует через эскалацию.")

# ---------------------------------------------------------- ШАГ 5. СВЕДЕНИЕ
W("\n--- ШАГ 5. СВЕДЕНИЕ ---")
IDX = {}
for x in ("criminal", "apt"):
    IDX[x] = (I[x]*100 * REACH[x]*100 * FON*100) ** (1/3)
    W(f"  Индекс({x:<8}) = ({I[x]*100:.2f} x {REACH[x]*100:.2f} x {FON*100:.2f})^(1/3) "
      f"= {IDX[x]:.2f}")
W("  Индекс(hacktivist) не считается: основание применимости недостаточно.")
lead = max(IDX, key=IDX.get)
W(f"\n  Приоритет = max = {IDX[lead]:.2f}   ведущая угроза: {lead}")
W(f"  Разрыв со вторым типом: {IDX[lead] - min(IDX.values()):.2f}")
full_min = min(min(FULL[x] for x in ("criminal", "apt")), full_reach)
W(f"  Связывающая полнота = {full_min:.4f}")

# ------------------------------------------------- СВЕРКА С КОНВЕЙЕРОМ
W("\n--- СВЕРКА С ПРОГОНОМ ВЫБОРКИ ---")
b = build(KEY)
checks = [("база", BASE, b["base"]),
          ("индекс criminal", IDX["criminal"], b["idx"]["criminal"]),
          ("индекс apt", IDX["apt"], b["idx"]["apt"]),
          ("полнота достижимости", full_reach, b["full_reach"]),
          ("связывающая полнота", full_min, b["full_min"])]
bad = []
for name, mine, theirs in checks:
    ok = abs(mine - theirs) < 1e-9
    W(f"  {name:<22} разбор {mine:.6f}  прогон {theirs:.6f}  {'совпало' if ok else 'РАСХОЖДЕНИЕ'}")
    if not ok: bad.append(name)
if a.day:
    W("  (дата задана явно, прогон выборки считает по свежим снимкам — "
      "расхождение здесь ожидаемо и означает лишь разные снимки)")
elif bad:
    raise SystemExit(f"\nРАЗБОР РАСХОДИТСЯ С КОНВЕЙЕРОМ: {', '.join(bad)}. "
                     "Это ошибка кода, а не данных: разбор обязан вызывать те же функции.")
else:
    W("  Разбор и прогон используют одни функции и дают одно число.")
