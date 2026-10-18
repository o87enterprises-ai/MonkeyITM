"""Stand-in for `broker export --db X --format json --out Y` in runner tests: copies the fake broker's
fake-log.json (next to the database path) to Y."""
import os, shutil, sys

a = sys.argv[1:]
if not a or a[0] != "export":
    sys.exit(2)
db, out = a[a.index("--db") + 1], a[a.index("--out") + 1]
src = os.path.join(os.path.dirname(db), "fake-log.json")
if not os.path.exists(src):
    sys.exit(1)
shutil.copy(src, out)
