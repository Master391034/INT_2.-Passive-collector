"""Государственные закупки по ИНН.

Автоматического доступа к реестру нет. Проверяется в ручную, принимает данные от аналитика."""
import argparse, json
try:
    from ._common import Log, save          # как часть пакета collect
except ImportError:
    from _common import Log, save          # при запуске файлом напрямую

def collect(obj, inn, contracts=None, day=None):
    log = Log()
    log.step(f"закупки по ИНН {inn}")
    log.url("https://zakupki.gov.ru/epz/contract/search/results.html")
    contracts = contracts or []
    d = {"found": bool(contracts), "inn": inn, "contracts": contracts,
         "state_contracts_sum": sum(c.get("sum", 0) for c in contracts) or None,
         "entry_method": "ручной ввод из zakupki.gov.ru",
         "status": "confirmed" if contracts else "not_found",
         "note": ("Пустой результат при выполненном запросе — подтверждённый ноль, "
                  "а не отсутствие проверки. Видна только государственная часть "
                  "контрактов, частные скрыты.")}
    log.ok(f"контрактов: {len(contracts)}" if contracts
           else "контрактов не найдено — подтверждённый ноль")
    save("zakupki", obj, d, log, day)
    return d

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--object", required=True); ap.add_argument("--inn", required=True)
    ap.add_argument("--contracts-json", help="файл со списком контрактов, если они есть")
    a = ap.parse_args()
    c = json.load(open(a.contracts_json)) if a.contracts_json else []
    collect(a.object, a.inn, c)
