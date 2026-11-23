#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(python3 -c 'import tomllib; print(tomllib.load(open("'"$ROOT"'/pyproject.toml", "rb"))["project"]["version"])')}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/bughunter-ai"

install -d "$PKG/DEBIAN" "$PKG/opt/bughunter-ai" "$PKG/usr/bin" "$PKG/usr/share/applications"

cp -a "$ROOT/app" "$ROOT/config" "$PKG/opt/bughunter-ai/"
install -m 0644 "$ROOT/main.py" "$PKG/opt/bughunter-ai/main.py"
install -m 0644 "$ROOT/requirements.txt" "$PKG/opt/bughunter-ai/requirements.txt"
install -m 0644 "$ROOT/requirements-desktop.txt" "$PKG/opt/bughunter-ai/requirements-desktop.txt"
install -m 0644 "$ROOT/pyproject.toml" "$PKG/opt/bughunter-ai/pyproject.toml"
install -m 0755 "$ROOT/packaging/bughunter-ai" "$PKG/usr/bin/bughunter-ai"
install -m 0755 "$ROOT/packaging/bughunter-ai-admin" "$PKG/usr/bin/bughunter-ai-admin"
install -m 0644 "$ROOT/packaging/bughunter-ai.desktop" "$PKG/usr/share/applications/bughunter-ai.desktop"

cat > "$PKG/DEBIAN/control" <<EOF
Package: bughunter-ai
Version: $VERSION
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.11), python3-venv, python3-pip, libgl1, libegl1, libdbus-1-3, libxkbcommon-x11-0
Maintainer: BugHunter AI
Description: Authorized security research desktop application
 Native PySide6 desktop workspace connected to the BugHunter AI cloud API.
EOF

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
APP_DIR=/opt/bughunter-ai
VENV="$APP_DIR/.venv"
if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --disable-pip-version-check --upgrade pip
"$VENV/bin/python" -m pip install --disable-pip-version-check -r "$APP_DIR/requirements-desktop.txt"
mkdir -p /usr/share/applications
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
echo "BugHunter AI installed. Launch it from the application menu or run: bughunter-ai"
echo "The first remote account must be provisioned once using bughunter-ai-admin."
exit 0
EOF

cat > "$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = "remove" ] || [ "${1:-}" = "purge" ]; then
    rm -rf /opt/bughunter-ai/.venv
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
EOF

chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/postrm"
mkdir -p "$ROOT/dist"
dpkg-deb --build --root-owner-group "$PKG" "$ROOT/dist/bughunter-ai_${VERSION}_all.deb"
echo "Built: $ROOT/dist/bughunter-ai_${VERSION}_all.deb"
