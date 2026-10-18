#!/usr/bin/env bash
# Build the public, open-source copy of this repository in a NEW directory with a fresh git history.
# This private repository is not changed. See opensource/README.md.
#
#   bash scripts/make-public-release.sh ../MonkeyITM-VM-public
#
# Then review the output, and push it to a new public repository yourself.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:?usage: make-public-release.sh <new output directory>}"
[ -e "$OUT" ] && { echo "$OUT already exists; give a new directory" >&2; exit 1; }
git diff --quiet HEAD -- . ':!Cargo.lock' || echo "note: uncommitted changes are NOT included (the release uses HEAD)" >&2

mkdir -p "$OUT"
git archive --format=tar HEAD | tar -x -C "$OUT"

# 1. Leave out the private paths.
while IFS= read -r p; do
  case "$p" in ''|'#'*) continue ;; esac
  rm -rf "${OUT:?}/${p%/}"
done < opensource/PRIVATE_PATHS.txt

# 2. The open-source licence files.
cp opensource/LICENSE-APACHE-2.0 "$OUT/LICENSE"
cp opensource/LICENSE-AGPL-3.0 "$OUT/site/LICENSE"
cp opensource/NOTICE opensource/TRADEMARKS.md opensource/CONTRIBUTING.md opensource/CLA.md opensource/SECURITY.md "$OUT/"
sed -i 's/^license = "LicenseRef-Proprietary"/license = "Apache-2.0"/' "$OUT/Cargo.toml"

# 3. What still says proprietary or confidential (needs rewording before the push).
echo "== files that still say proprietary / confidential / all rights reserved (reword before pushing):"
grep -rliE 'proprietary|all rights reserved|confidential' "$OUT" --exclude-dir=.git --exclude=LICENSE --exclude=CLA.md --exclude=SECURITY.md || echo "   (none)"

# 4. One fresh commit.
cd "$OUT"
git init -q -b main
git add -A
git -c user.name="Daniel Oden" -c user.email="${RELEASE_EMAIL:-noreply@o87.invalid}" commit -qm "MonkeyITM-VM: initial open-source release (Apache-2.0; site/ AGPL-3.0)"
echo "== built $OUT: $(git ls-files | wc -l) files, one commit. Review it, then:"
echo "   git remote add origin https://github.com/<org>/<new-public-repo>.git && git push -u origin main"
