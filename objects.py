"""Оценочная выборка. Перечень лежит в data/objects.json: это данные,
а не код, и инструмент запускается на любом своём перечне."""
from inputs import require

_d = require("objects.json")
EVALUATED = _d["objects"]
REVENUE = {o["key"]: o["revenue"] for o in EVALUATED}
ADDRESSES = {o["key"]: o.get("addresses") for o in EVALUATED}

BY_KEY = {o["key"]: o for o in EVALUATED}
# Прежние написания ведут на ту же запись: объект не теряется из-за того,
# каким именем его назвали при запуске.
for _o in EVALUATED:
    for _a in _o.get("aliases") or []:
        BY_KEY.setdefault(_a, _o)
