"""Сведения о службах на подтверждённых узлах через Censys Platform.

Запрос идёт ПО АДРЕСАМ, подтверждённым на шаге DNS, а не по домену. Это снимает
ограничение «привязка адреса к организации неточна»: привязку cвоя,
полученную из DNS объекта, а не оператора сканера.

Токен читается из переменной окружения и никуда не записывается: ни в снимок,
ни в журнал. Censys сам предупреждает, что токен действует от имени владельца
аккаунта и обращаться с ним следует как с паролем.

Тариф накладывает ограничение: одно одновременное действие. Поэтому запросы
строго последовательны, без потоков."""
import os, json, time, urllib.request, urllib.error, argparse, sys
try:
    from ._common import Log, save          # как часть пакета collect
except ImportError:
    from _common import Log, save          # при запуске файлом напрямую
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from paths import snapshot, latest_day

TOKEN_ENV = "CENSYS_TOKEN"
ORG_ENV   = "CENSYS_ORG"          # если аккаунт его требует
BASE_ENV  = "CENSYS_API_BASE"
# Censys Platform API, docs.censys.com/reference:
DEFAULT_BASE = "https://api.platform.censys.io"
ACCEPT = "application/vnd.censys.api.v3.host.v1+json"

def addresses_from_dns(obj, day=None):
    """Адреса из снимка DNS того же объекта: только подтверждённые."""
    # Снимок DNS берётся по своей дате: Censys ограничен тарифом и запускается
    # отдельно, часто в другой день.
    from paths import latest_for
    if day:
        path = snapshot(obj, day, "dns")
    else:
        day, path = latest_for(obj, "dns")
    if path is None or not path.exists():
        raise FileNotFoundError(f"{obj}: снимка DNS нет — адреса брать не из чего")
    d = json.load(open(path))["data"]
    addrs = set(d.get("a") or [])
    addrs |= set((d.get("addresses") or {}).keys())
    return sorted(addrs), day

def consent_block(obj, addrs, base):
    print()
    print("=" * 74)
    print("  ШАГ: сведения о службах на подтверждённых узлах (Censys)")
    print("=" * 74)
    print(f"  Этот шаг выполняется под вашим аккаунтом Censys. Будет сделано:")
    print()
    print(f"    запросов к API:        {len(addrs)}")
    print(f"    по адресам:            {', '.join(addrs) if addrs else '— адресов нет'}")
    print(f"    источник адресов:      записи A, подтверждённые на шаге DNS")
    print(f"    что запрашивается:     открытые службы, порты, баннеры, версии ПО")
    print(f"    что НЕ выполняется:    обращений к перечисленным узлам не производится;")
    print(f"                           читается база оператора сканера")
    print(f"    базовый адрес API:     {base or '(не задан)'}")
    print()
    print(f"  Оценка расхода: {len(addrs)} кредитов при цене 1 кредит за lookup.")
    print(f"  Бесплатных действий в сутки на тарифе Free: 5 — они расходуются первыми.")
    print()
    print(f"  Токен используется только в этом шаге, из переменной {TOKEN_ENV},")
    print(f"  без записи на диск и в журнал.")
    print()
    print(f"  Пропуск шага не ломает прогон: группа «периметр» будет посчитана")
    print(f"  без признаков версий ПО, и это отразится в полноте наблюдения.")
    print("=" * 74)

def lookup(ip, token, base, org, log):
    """Один asset lookup. Возвращает (данные, состояние).
    Любая ошибка — это not_checked с причиной, и никогда not_found:
    отказ источника не является отсутствием служб."""
    url = f"{base.rstrip('/')}/v3/global/asset/host/{ip}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": ACCEPT,
        "User-Agent": "targetmap/1.0",
        **({"X-Organization-ID": org} if org else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.load(r), "confirmed"
    except urllib.error.HTTPError as e:
        body = e.read()[:300].decode("utf-8", "replace")
        log.fail(f"{ip}: HTTP {e.code}. {body}")
        if e.code in (401, 403):
            log.fail("проверьте токен и, если аккаунт его требует, Organization ID")
        if e.code == 404:
            log.warn(f"{ip}: в базе оператора записи нет — это отсутствие записи, "
                     f"а не отсутствие служб")
        if e.code == 429:
            log.fail("исчерпан лимит или превышена частота: тариф допускает "
                     "одно одновременное действие")
        return None, ("not_found" if e.code == 404 else "not_checked")
    except Exception as e:
        log.fail(f"{ip}: {type(e).__name__}: {e}")
        return None, "not_checked"

def collect(obj, dry_run=False, day=None):
    log = Log()
    addrs, dns_day = addresses_from_dns(obj, day)
    base  = os.environ.get(BASE_ENV) or DEFAULT_BASE
    token = os.environ.get(TOKEN_ENV, "")
    org   = os.environ.get(ORG_ENV, "")
    log.step(f"адресов из снимка DNS за {dns_day}: {len(addrs)}")
    consent_block(obj, addrs, base)

    if dry_run:
        log.warn("--dry-run: ни одного запроса не выполнено, кредиты не израсходованы")
        return {"dry_run": True, "addresses": addrs, "estimated_credits": len(addrs)}
    if not token:
        log.fail(f"переменная {TOKEN_ENV} не задана — шаг пропущен")
        save("censys", obj, {"found": False, "status": "not_checked",
                             "reason": f"{TOKEN_ENV} не задана"}, log, day)
        return None
    if input("  Продолжить? [д/н] ").strip().lower() not in ("д", "y", "да", "yes"):
        log.warn("шаг отменён пользователем")
        save("censys", obj, {"found": False, "status": "not_checked",
                             "reason": "отменено пользователем"}, log, day)
        return None

    hosts, states = {}, {}
    for i, ip in enumerate(addrs, 1):
        log.step(f"[{i}/{len(addrs)}] lookup {ip}")
        data, st = lookup(ip, token, base, org, log)
        states[ip] = st
        if data: hosts[ip] = data; log.ok(f"{ip}: ответ получен")
        if i < len(addrs): time.sleep(1.2)      # одно одновременное действие
    d = {"found": bool(hosts), "addresses": addrs, "states": states, "hosts": hosts,
         "note": ("Запрос выполнен по адресам, подтверждённым в DNS объекта. "
                  "Обращений к узлам объекта не производилось: читалась база "
                  "оператора сканера."),
         "limitation": ("Баннер может быть недостоверен, снимок устаревает. "
                        "Версия, не указанная в баннере, даёт состояние «неизвестно», "
                        "а не ноль.")}
    save("censys", obj, d, log, day)
    return d

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--object", required=True)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    collect(a.object, a.dry_run)
