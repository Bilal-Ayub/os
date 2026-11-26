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
install -D -m 0644 "$REPO/core/etc/escrow/path.sh"     "$R/etc/escrow/path.sh"
finish escrow-shims

# ---- escrow-branding
# HOME_URL for os-release: the git remote as an https URL, if there is one.
HOME_URL="$(git -c safe.directory="$REPO" -C "$REPO" remote get-url origin 2>/dev/null \
    | sed -e 's|^git@github.com:|https://github.com/|' -e 's|\.git$||')" || HOME_URL=""
R="$STAGE/escrow-branding"
B="$REPO/branding"
control escrow-branding
sed -i "s|@VERSION@|$VERSION|g; s|@HOME_URL@|$HOME_URL|g" "$R/DEBIAN/postinst"
install -D -m 0755 "$B/files/etc/update-motd.d/05-escrow"   "$R/etc/update-motd.d/05-escrow"
install -D -m 0644 "$B/files/etc/default/grub.d/escrow.cfg" "$R/etc/default/grub.d/escrow.cfg"
install -D -m 0644 "$B/files/etc/xdg/autostart/escrow-xfce-wallpaper.desktop" \
                                                          "$R/etc/xdg/autostart/escrow-xfce-wallpaper.desktop"
install -D -m 0755 "$B/files/usr/lib/escrow/escrow-xfce-wallpaper" "$R/usr/lib/escrow/escrow-xfce-wallpaper"
install -D -m 0644 "$B/files/usr/share/glib-2.0/schemas/90_escrow-branding.gschema.override" \
                                                          "$R/usr/share/glib-2.0/schemas/90_escrow-branding.gschema.override"
install -D -m 0644 "$B/art/escrow-wallpaper.jpg"            "$R/usr/share/backgrounds/escrow/escrow-wallpaper.jpg"
install -D -m 0644 "$B/art/escrow-os.png"                   "$R/usr/share/icons/hicolor/256x256/apps/escrow-os.png"
install -D -m 0644 "$B/art/escrow-os.png"                   "$R/usr/share/pixmaps/escrow-os.png"
install -D -m 0644 "$REPO/LICENSE"                          "$R/usr/share/doc/escrow-branding/copyright"
printf '%s\n' /etc/update-motd.d/05-escrow /etc/default/grub.d/escrow.cfg \
    /etc/xdg/autostart/escrow-xfce-wallpaper.desktop > "$R/DEBIAN/conffiles"
chmod 0644 "$R/DEBIAN/conffiles"
finish escrow-branding

ls -l "$OUT"/*.deb
