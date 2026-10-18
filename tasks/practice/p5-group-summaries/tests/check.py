import sys
try:
    lines = [l for l in open("/workspace/summaries.txt").read().splitlines() if l.strip()]
except OSError:
    sys.exit("summaries.txt is missing")
if len(lines) != 3:
    sys.exit(f"expected 3 lines, got {len(lines)}")
for line, word in zip(lines, ("march", "june", "april")):
    if word not in line.lower():
        sys.exit(f"missing {word}")
print("ok")
