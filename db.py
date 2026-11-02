# Схема базы. SQLite: один файл, длинный формат — одна строка на наблюдение.
import sqlite3, pathlib

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
  object_key TEXT PRIMARY KEY,
  inn TEXT, domain TEXT, brand TEXT,
  alias_of TEXT,                      -- указатель на основную запись после слияния
  role TEXT                           -- reference | evaluated
);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY,
  object_key TEXT NOT NULL,
  feature TEXT NOT NULL,              -- код из features.py
  value_num REAL, value_text TEXT,
  status TEXT NOT NULL,               -- confirmed|not_found|not_checked|unknown
  source TEXT NOT NULL,
  snapshot_date TEXT NOT NULL,        -- когда получили
  event_date TEXT,                    -- к какому моменту относится
  publish_date TEXT,                  -- когда опубликовано: отбор ретроспективы идёт по нему
  reliability TEXT, credibility INTEGER,
  predicate TEXT NOT NULL,            -- passed|failed|not_applicable
  pred_reason TEXT,
  direction TEXT, grp INTEGER,
  raw_path TEXT,
  UNIQUE(object_key, feature, source, snapshot_date, value_text)
);
CREATE INDEX IF NOT EXISTS obs_obj  ON observations(object_key, feature);
CREATE INDEX IF NOT EXISTS obs_calc ON observations(object_key, predicate, grp);

-- только то, что идёт в расчёт
CREATE VIEW IF NOT EXISTS v_calc AS
SELECT object_key, feature, value_num, value_text, direction, grp, reliability, credibility
FROM observations WHERE predicate='passed' AND status='confirmed';

-- лог ненайденного: три блока одним запросом
CREATE VIEW IF NOT EXISTS v_gaps AS
SELECT object_key, feature, source,
  CASE WHEN status='not_found'   THEN 'не обнаружено'
       WHEN status='not_checked' THEN 'не проверено'
       WHEN predicate='failed'   THEN 'исключено предикатом' END AS block,
  COALESCE(pred_reason,'') AS reason
FROM observations
WHERE status IN ('not_found','not_checked') OR predicate='failed';
"""

def open_db(path="data/observations.db"):
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)          # идемпотентно: IF NOT EXISTS везде
    con.row_factory = sqlite3.Row
    return con

def put(con, **kw):
    """Записать наблюдение. Отсутствующие поля -> NULL.
    OR IGNORE, чтобы повторный прогон того же дня не падал на UNIQUE."""
    cols = ("object_key","feature","value_num","value_text","status","source",
            "snapshot_date","event_date","publish_date","reliability","credibility",
            "predicate","pred_reason","direction","grp","raw_path")
    vals = [kw.get(c) for c in cols]
    con.execute(f"INSERT OR IGNORE INTO observations ({','.join(cols)}) "
                f"VALUES ({','.join('?'*len(cols))})", vals)
