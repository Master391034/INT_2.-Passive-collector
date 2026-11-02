#!/bin/sh
# Полный расчёт по уже собранным снимкам. Сеть не используется.
set -e
D="${TARGETMAP_DATA:-data_demo}"
export TARGETMAP_DATA="$D"
echo "== набор данных: $D"
python3 full_run.py
python3 db_load.py
python3 exports_build.py
echo "== разбор одного объекта"
python3 trace.py --object "$(python3 -c "import json,os;print(json.load(open(os.environ['TARGETMAP_DATA']+'/objects.json'))['objects'][0]['key'])")"
