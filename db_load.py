"""Наполнение базы наблюдений из рассчитанного прогона.

Одна строка на наблюдение, включая отрицательные и непроверенные: лог
ненайденного строится запросом к той же таблице, а не отдельным файлом.
"""
import argparse, json
from db import open_db, put
from full_run import build, KEYS, ADDRESSES, REVENUE
from normalize import perimeter, third_party, vendors_from_fingerprint
from objects import BY_KEY
from paths import DB, spread

SRC = {"INT.PAY": "ГИР БО, строка 2110", "INT.DATA": "лицензия/оферта объекта",
       "INT.GOV": "федеральный реестр ОМС", "INT.CRIT": "ТРМО либо аналитик"}
CRED = {"INT.PAY": 1, "INT.DATA": 2, "INT.GOV": 1, "INT.CRIT": None}


def load(path=None, verbose=True):
    con = open_db(str(path or DB))
    n = 0
    for key in KEYS:
        o = BY_KEY[key]
        r = build(key)
        sp = spread(key)
        day = max([d for d in sp.values() if d] or ["—"])
        con.execute("INSERT OR REPLACE INTO objects (object_key, inn, domain, brand, role) "
                    "VALUES (?,?,?,?,?)", (key, o["inn"], o["domain"], o["brand"], "evaluated"))

        # --- признаки интереса
        for f, v in r["vals"].items():
            put(con, object_key=key, feature=f, value_num=v, status="confirmed",
                source=SRC[f], snapshot_date=day, predicate="passed",
                reliability="A", credibility=CRED[f] or 3, grp=0)
            n += 1
        for f, why in (("INT.PUB", "сборщика упоминаний нет"),
                       ("INT.LINK", "референсного распределения нет")):
            put(con, object_key=key, feature=f, status="not_checked", source="—",
                snapshot_date=day, predicate="not_applicable", pred_reason=why, grp=0)
            n += 1

        # --- периметр: каждый адрес, включая исключённые
        vd, _, _ = vendors_from_fingerprint(key)
        per = perimeter(key, o["domain"], vendor_domains=vd)
        for cls, rows in (("own", per["own"]), ("supplier", per["supplier"]),
                          ("unchecked", per["unchecked"]), ("excluded", per["excluded"])):
            for x in rows:
                asset = "asset" in x
                put(con, object_key=key, feature="REA.HOST", value_text=x["ip"],
                    status="confirmed" if asset else x.get("service_state", "not_checked"),
                    source="censys + dns", snapshot_date=sp.get("censys") or day,
                    reliability="A", credibility=3,
                    predicate="passed" if asset else "failed",
                    pred_reason=x.get("reason") or x.get("service_reason"),
                    direction="exploit", grp=2,
                    raw_path=f"data/raw/{key}/{sp.get('censys')}/censys.json")
                n += 1

        # --- почтовый канал
        for m in per["mail"]:
            put(con, object_key=key, feature=m["feature"], value_num=m.get("value_num"),
                value_text=m.get("note") or m.get("reason"), status=m["status"],
                source="dns", snapshot_date=sp.get("dns") or day,
                reliability=m.get("reliability"), credibility=m.get("credibility"),
                predicate="passed" if (m.get("value_num") or 0) > 0 else "failed",
                pred_reason=m.get("note"), direction="phishing", grp=2,
                raw_path=f"data/raw/{key}/{sp.get('dns')}/dns.json")
            n += 1

        # --- третья сторона по глубинам
        for d in r["tp_detail"]:
            if d.get("depth"):
                put(con, object_key=key, feature=f"REA.DEP{d['depth']}",
                    value_num=1.0, value_text=d["kind"], status="confirmed",
                    source=d["what"][:200], snapshot_date=day,
                    reliability="A", credibility=d["credibility"],
                    predicate="passed", direction="third_party", grp=3)
            else:
                put(con, object_key=key, feature="REA.DEP",
                    status="not_found" if r["P3"] is not None else "not_checked",
                    source="разметка, привязка адресов, автономная система",
                    snapshot_date=day, predicate="not_applicable",
                    pred_reason=d["what"], direction="third_party", grp=3)
            n += 1

        # --- группа индикаторов компрометации: исключена по этическому решению
        put(con, object_key=key, feature="REA.CRED", status="not_checked",
            source="—", snapshot_date=day, predicate="not_applicable",
            pred_reason="источник не используется по этическому решению", grp=1)
        n += 1

    con.commit()
    if verbose:
        print(f"записано наблюдений: {n}")
        for row in con.execute("SELECT status, COUNT(*) c FROM observations "
                               "GROUP BY status ORDER BY c DESC"):
            print(f"  {row['status']:<12} {row['c']}")
        print("\nлог ненайденного из представления v_gaps:")
        for row in con.execute("SELECT block, COUNT(*) c FROM v_gaps "
                               "GROUP BY block ORDER BY c DESC"):
            print(f"  {row['block']:<22} {row['c']}")
    return con


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Наполнить базу наблюдений из прогона")
    ap.add_argument("--db", help="путь к файлу базы")
    load(ap.parse_args().db)
