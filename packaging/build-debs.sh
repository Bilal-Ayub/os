#!/usr/bin/env bash
# Build escrow_<v>_all.deb and escrow-shims_<v>_all.deb into build/.
# Needs only dpkg-deb (part of dpkg, present on every Debian/Ubuntu system).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$REPO/core/escrow/__init__.py")"
OUT="$REPO/build"
STAGE="$(mktemp -d)"          # stage on a Linux fs: dpkg-deb checks permissions
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$OUT"

control() {  # control <pkg>: copy DEBIAN/, fill in the version, fix modes
    local pkg="$1" root="$STAGE/$1"
    mkdir -p "$root/DEBIAN"
    cp "$REPO/packaging/$pkg/DEBIAN/"* "$root/DEBIAN/"
    sed -i "s/@VERSION@/$VERSION/g" "$root/DEBIAN/control"
    chmod 0755 "$root/DEBIAN"
    for f in "$root/DEBIAN/"*; do
        case "$(basename "$f")" in
            postinst|prerm|postrm|preinst) chmod 0755 "$f" ;;
            *) chmod 0644 "$f" ;;
        esac
    done
}

finish() {  # finish <pkg>: md5sums, size, build
    local pkg="$1" root="$STAGE/$1"
    (cd "$root" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' \
        | sort -z | xargs -0 -r md5sum > DEBIAN/md5sums)
    chmod 0644 "$root/DEBIAN/md5sums"
    echo "Installed-Size: $(du -sk --exclude=DEBIAN "$root" | cut -f1)" >> "$root/DEBIAN/control"
    dpkg-deb --root-owner-group -Zxz --build "$root" "$OUT/${pkg}_${VERSION}_all.deb"
}

# ---- escrow
R="$STAGE/escrow"
control escrow
install -D -m 0755 "$REPO/core/bin/escrow"             "$R/usr/bin/escrow"
install -D -m 0755 "$REPO/core/libexec/escrow-enter"   "$R/usr/lib/escrow/escrow-enter"
install -d -m 0755 "$R/usr/lib/escrow/escrow"
install -m 0644 "$REPO"/core/escrow/*.py               "$R/usr/lib/escrow/escrow/"
install -D -m 0644 "$REPO/core/etc/apparmor.d/escrow"  "$R/etc/apparmor.d/escrow"
install -D -m 0644 "$REPO/core/etc/escrow.toml"        "$R/etc/escrow/escrow.toml"
install -D -m 0644 "$REPO/README.md"                   "$R/usr/share/doc/escrow/README.md"
install -D -m 0644 "$REPO/LICENSE"                     "$R/usr/share/doc/escrow/copyright"
install -D -m 0755 "$REPO/demo/rogue-agent.sh"         "$R/usr/share/doc/escrow/examples/rogue-agent.sh"
install -D -m 0755 "$REPO/demo/run-demo.sh"            "$R/usr/share/doc/escrow/examples/run-demo.sh"
finish escrow

# ---- escrow-shims
R="$STAGE/escrow-shims"
control escrow-shims
install -D -m 0755 "$REPO/core/libexec/escrow-shim"    "$R/usr/lib/escrow/escrow-shim"
install -d -m 0755 "$R/usr/lib/escrow/shims" "$R/etc/escrow/agents.d"
for f in "$REPO"/core/etc/agents.d/*.toml; do
    name="$(basename "$f" .toml)"
    install -m 0644 "$f" "$R/etc/escrow/agents.d/"
    ln -s ../escrow-shim "$R/usr/lib/escrow/shims/$name"
done
install -D -m 0644 "$REPO/core/etc/profile.d/escrow.sh" "$R/etc/profile.d/escrow.sh"
finish escrow-shims

ls -l "$OUT"/*.deb
