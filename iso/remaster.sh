#!/usr/bin/env bash
# Build the Escrow OS live/install ISO by remastering Xubuntu Minimal 26.04.
#
#   bash packaging/build-debs.sh                       # as your user, first
#   sudo bash iso/remaster.sh [path/to/xubuntu-26.04.1-minimal-amd64.iso]
#
# Needs: root, xorriso, squashfs-tools, python3. Optional: MODEL=<gguf> (default:
# ~$SUDO_USER/models/qwen2.5-1.5b-instruct-q4_k_m.gguf) ships the local model
# for `escrow explain` and enables escrow-llm.service; MODEL=none skips it.
#
# What it does:
#   1. unpack casper/minimal.squashfs (the installed system) and chroot into it;
#   2. apt-install escrow, escrow-shims, escrow-branding (+ git, apparmor,
#      llama.cpp-tools), add the model and its sandboxed service, Xfce/LightDM
#      wallpaper defaults;
#   3. repack it, and fix the live layer (minimal.live.squashfs): it carries its
#      own dpkg status and linker cache, which would hide what step 2 installed;
#   4. rename the GRUB entries and .disk/info, update sizes, manifests and
#      md5sum.txt, and write a new ISO with xorriso, replaying the original
#      boot setup (BIOS + UEFI, Secure Boot shim untouched).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$REPO/core/escrow/__init__.py")"
USER_HOME="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)"
ISO_IN="${1:-$USER_HOME/iso-build/xubuntu-26.04.1-minimal-amd64.iso}"
OUTDIR="$(dirname "$(readlink -f "$ISO_IN")")"
ISO_OUT="$OUTDIR/escrow-os-$VERSION-amd64.iso"
WORK="$OUTDIR/work"
MODEL="${MODEL:-$USER_HOME/models/qwen2.5-1.5b-instruct-q4_k_m.gguf}"
BASE=minimal
LIVE=minimal.live

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die() { echo "remaster: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run with sudo"
for t in xorriso unsquashfs mksquashfs python3; do command -v $t >/dev/null || die "$t is missing (sudo apt install xorriso squashfs-tools)"; done
[ -f "$ISO_IN" ] || die "no ISO at $ISO_IN"
DEBS=("$REPO"/build/escrow_"$VERSION"_all.deb "$REPO"/build/escrow-shims_"$VERSION"_all.deb "$REPO"/build/escrow-branding_"$VERSION"_all.deb)
for d in "${DEBS[@]}"; do [ -f "$d" ] || die "missing $d: run packaging/build-debs.sh first"; done
if [ "$MODEL" != none ] && [ ! -f "$MODEL" ]; then echo "remaster: no model at $MODEL; building without it"; MODEL=none; fi

ROOT="$WORK/root"          # minimal.squashfs, unpacked
LIVEDIR="$WORK/live"       # minimal.live.squashfs, unpacked (an overlay upper layer)
ISOFILES="$WORK/iso"       # small files taken out of / put back into the ISO

cleanup() {
    for m in "$ROOT/dev/pts" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/run" "$WORK/merged"; do
        mountpoint -q "$m" 2>/dev/null && umount -l "$m" || true
    done
}
trap cleanup EXIT

say "0. Fresh work dir: $WORK"
cleanup
rm -rf "$WORK"
mkdir -p "$WORK" "$ISOFILES"
xorriso -osirrox on -indev "$ISO_IN" \
    -extract /casper/install-sources.yaml "$ISOFILES/install-sources.yaml" \
    -extract /boot/grub/grub.cfg "$ISOFILES/grub.cfg" \
    -extract /boot/grub/loopback.cfg "$ISOFILES/loopback.cfg" \
    -extract /.disk/info "$ISOFILES/info" \
    -extract /md5sum.txt "$ISOFILES/md5sum.txt" \
    -extract /casper/$BASE.squashfs "$WORK/$BASE.squashfs" \
    -extract /casper/$LIVE.squashfs "$WORK/$LIVE.squashfs" 2>&1 | tail -1
chmod -R u+w "$ISOFILES"
COMP="$(unsquashfs -s "$WORK/$BASE.squashfs" | sed -n 's/^Compression \(.*\)/\1/p')"
BLOCK="$(unsquashfs -s "$WORK/$BASE.squashfs" | sed -n 's/^Block size \([0-9]*\)/\1/p')"
echo "squashfs: compression=$COMP block=$BLOCK"

say "1. Unpack $BASE.squashfs and $LIVE.squashfs"
unsquashfs -q -d "$ROOT" "$WORK/$BASE.squashfs"
unsquashfs -q -d "$LIVEDIR" "$WORK/$LIVE.squashfs"
rm "$WORK/$BASE.squashfs"
cp "$ROOT/var/lib/dpkg/status" "$WORK/status.before"

say "2. Install Escrow OS into the base system (chroot)"
mount --bind /dev "$ROOT/dev"
mount --bind /dev/pts "$ROOT/dev/pts"
mount -t proc proc "$ROOT/proc"
mount -t sysfs sysfs "$ROOT/sys"
mount -t tmpfs tmpfs "$ROOT/run"
mv "$ROOT/etc/resolv.conf" "$WORK/resolv.conf.orig" 2>/dev/null || true
cat /etc/resolv.conf > "$ROOT/etc/resolv.conf"
printf '#!/bin/sh\nexit 101\n' > "$ROOT/usr/sbin/policy-rc.d"; chmod 755 "$ROOT/usr/sbin/policy-rc.d"
mkdir -p "$ROOT/tmp/escrow-debs"
cp "${DEBS[@]}" "$ROOT/tmp/escrow-debs/"
EXTRA="git apparmor"
[ "$MODEL" != none ] && EXTRA="$EXTRA llama.cpp-tools"
# The image's own sources include file:/cdrom (valid only when booted from the
# disc), so the build uses a temporary, signed archive list and leaves those alone.
CODENAME="$(. "$ROOT/etc/os-release"; echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
KEY=/usr/share/keyrings/ubuntu-archive-keyring.gpg
[ -f "$ROOT$KEY" ] || die "no $KEY in the image"
{
    for suite in "$CODENAME" "$CODENAME-updates" "$CODENAME-security"; do
        echo "deb [signed-by=$KEY] http://archive.ubuntu.com/ubuntu $suite main universe"
    done
} > "$ROOT/tmp/escrow-build.list"
APTOPT="-o Dir::Etc::SourceList=/tmp/escrow-build.list -o Dir::Etc::SourceParts=/nonexistent"
chroot "$ROOT" /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin DEBIAN_FRONTEND=noninteractive HOME=/root \
    sh -c "apt-get $APTOPT update -qq && apt-get $APTOPT install -y -q --no-install-recommends /tmp/escrow-debs/*.deb $EXTRA"
rm -f "$ROOT/tmp/escrow-build.list"

if [ "$MODEL" != none ]; then
    install -D -m 0644 "$MODEL" "$ROOT/usr/share/escrow/models/$(basename "$MODEL")"
    install -D -m 0644 "$REPO/iso/files/escrow-llm.service" "$ROOT/etc/systemd/system/escrow-llm.service"
    ln -sf /etc/systemd/system/escrow-llm.service "$ROOT/etc/systemd/system/multi-user.target.wants/escrow-llm.service"
    # point escrow explain at it explicitly
    sed -i 's|^# url = "http://127.0.0.1:8080/v1"|url = "http://127.0.0.1:8080/v1"|' "$ROOT/etc/escrow/escrow.toml"
fi

# Live session: stage escrow sessions on tmpfs (the live root is an overlayfs,
# which overlayfs cannot use as an upper dir). Inert on an installed system.
install -D -m 0644 "$REPO/iso/files/var-lib-escrow.mount" "$ROOT/etc/systemd/system/var-lib-escrow.mount"
mkdir -p "$ROOT/etc/systemd/system/local-fs.target.wants"
ln -sf /etc/systemd/system/var-lib-escrow.mount "$ROOT/etc/systemd/system/local-fs.target.wants/var-lib-escrow.mount"

# Desktop: the Xfce wallpaper and dark theme are set per user at first login by escrow-branding's
# autostart helper (xfdesktop 4.20 has no system-wide image key to edit).
# LightDM greeter: wallpaper and dark theme (Greybird-dark ships with Xubuntu):
WP=/usr/share/backgrounds/escrow/escrow-wallpaper.jpg
if [ -d "$ROOT/etc/lightdm" ]; then
    mkdir -p "$ROOT/etc/lightdm/lightdm-gtk-greeter.conf.d"
    { printf '[greeter]\nbackground=%s\n' "$WP"
      [ -d "$ROOT/usr/share/themes/Greybird-dark" ] && echo "theme-name=Greybird-dark"
    } > "$ROOT/etc/lightdm/lightdm-gtk-greeter.conf.d/90-escrow.conf"
fi
# The installed system's GRUB menu: written by update-grub on install, reads grub.d/escrow.cfg.

chroot "$ROOT" sh -c 'apt-get clean; rm -rf /var/lib/apt/lists/* /tmp/escrow-debs'
rm -f "$ROOT/usr/sbin/policy-rc.d" "$ROOT/etc/resolv.conf"
[ -e "$WORK/resolv.conf.orig" ] || [ -L "$WORK/resolv.conf.orig" ] && mv "$WORK/resolv.conf.orig" "$ROOT/etc/resolv.conf"
chroot "$ROOT" dpkg-query -W --showformat='${Package}\t${Version}\n' > "$WORK/$BASE.manifest"
grep -E '^(escrow|llama|git|apparmor)' "$WORK/$BASE.manifest" || true
cleanup
cp "$ROOT/var/lib/dpkg/status" "$WORK/status.after"

say "3. Fix the live layer ($LIVE): dpkg status, diversions, linker cache"
python3 - "$WORK/status.before" "$WORK/status.after" "$LIVEDIR/var/lib/dpkg/status" \
          "$ROOT/var/lib/dpkg/diversions" "$LIVEDIR/var/lib/dpkg/diversions" <<'PY'
import os, sys
before, after, live, base_div, live_div = sys.argv[1:]
def paras(path):
    if not os.path.exists(path):
        return {}
    out = {}
    for block in open(path, encoding="utf-8").read().split("\n\n"):
        block = block.strip("\n")
        if not block:
            continue
        f = dict(l.split(": ", 1) for l in block.splitlines() if ": " in l and not l.startswith(" "))
        out[(f.get("Package"), f.get("Architecture"))] = block
    return out
if os.path.exists(live):
    b, a, l = paras(before), paras(after), paras(live)
    added = changed = 0
    for k, blk in a.items():
        if k not in b and k not in l:
            l[k] = blk; added += 1
        elif k in b and b[k] != blk and l.get(k) == b[k]:
            l[k] = blk; changed += 1
    with open(live, "w", encoding="utf-8") as f:
        f.write("\n\n".join(l[k] for k in sorted(l, key=lambda k: (k[0] or "", k[1] or ""))) + "\n")
    print(f"live dpkg status: +{added} packages, {changed} updated")
else:
    print("live layer has no dpkg status of its own: nothing to merge")
if os.path.exists(live_div):
    def triples(p):
        ls = open(p).read().splitlines()
        return [tuple(ls[i:i + 3]) for i in range(0, len(ls) - len(ls) % 3, 3)]
    lt, bt = triples(live_div), triples(base_div)
    new = [t for t in bt if t not in lt]
    with open(live_div, "a") as f:
        for t in new:
            f.write("\n".join(t) + "\n")
    print(f"live diversions: +{len(new)}")
PY
if [ -e "$LIVEDIR/etc/ld.so.cache" ]; then
    mkdir -p "$WORK/merged" "$WORK/ovl-work"
    mount -t overlay overlay -o "lowerdir=$ROOT,upperdir=$LIVEDIR,workdir=$WORK/ovl-work,index=off,redirect_dir=off,metacopy=off,xino=off" "$WORK/merged"
    ldconfig -r "$WORK/merged"
    umount "$WORK/merged"
    rm -rf "$WORK/ovl-work" "$WORK/merged"
    # drop bookkeeping xattrs the temporary overlay may have left on the upper dir
    python3 - "$LIVEDIR" <<'PY'
import os, sys
n = 0
for dp, dns, fns in os.walk(sys.argv[1]):
    for p in [dp] + [os.path.join(dp, x) for x in fns]:
        try:
            for a in os.listxattr(p, follow_symlinks=False):
                if a in ("trusted.overlay.origin", "trusted.overlay.impure", "trusted.overlay.nlink"):
                    os.removexattr(p, a, follow_symlinks=False); n += 1
        except OSError:
            pass
print(f"live linker cache regenerated; {n} temporary overlay xattrs removed")
PY
fi

say "4. Repack the squashfs layers ($COMP)"
mksquashfs "$ROOT" "$WORK/$BASE.squashfs" -comp "$COMP" -b "$BLOCK" -noappend -quiet -progress
mksquashfs "$LIVEDIR" "$WORK/$LIVE.new.squashfs" -comp "$COMP" -b "$BLOCK" -noappend -quiet
BASE_SIZE="$(du -sx --block-size=1 "$ROOT" | cut -f1)"
LIVE_SIZE="$(du -sx --block-size=1 "$LIVEDIR" | cut -f1)"
echo "$BASE_SIZE" > "$ISOFILES/$BASE.size"
echo "$LIVE_SIZE" > "$ISOFILES/$LIVE.size"
cp "$WORK/$BASE.manifest" "$ISOFILES/$BASE.manifest"
sed -i "s/^  size: [0-9]*/  size: $BASE_SIZE/" "$ISOFILES/install-sources.yaml"
sed -i -e 's/Xubuntu Minimal/Escrow OS (Xubuntu Minimal base)/' -e 's/A minimal installation of the Xubuntu Desktop./Escrow OS: Xubuntu Minimal with AI agents run as reversible transactions./' "$ISOFILES/install-sources.yaml"
rm -rf "$ROOT" "$LIVEDIR"

say "5. Boot menu and disk label text"
for f in grub.cfg loopback.cfg; do
    sed -i -e 's/Try or Install Xubuntu/Try or Install Escrow OS/' -e 's/"Xubuntu (safe graphics)"/"Escrow OS (safe graphics)"/' "$ISOFILES/$f"
done
printf 'Escrow OS %s (based on %s)\n' "$VERSION" "$(cat "$ISOFILES/info")" > "$ISOFILES/info"
grep menuentry "$ISOFILES/grub.cfg"; cat "$ISOFILES/info"

say "6. Write $ISO_OUT"
declare -A MAP=(
    ["/casper/$BASE.squashfs"]="$WORK/$BASE.squashfs"
    ["/casper/$LIVE.squashfs"]="$WORK/$LIVE.new.squashfs"
    ["/casper/$BASE.size"]="$ISOFILES/$BASE.size"
    ["/casper/$LIVE.size"]="$ISOFILES/$LIVE.size"
    ["/casper/$BASE.manifest"]="$ISOFILES/$BASE.manifest"
    ["/casper/install-sources.yaml"]="$ISOFILES/install-sources.yaml"
    ["/boot/grub/grub.cfg"]="$ISOFILES/grub.cfg"
    ["/boot/grub/loopback.cfg"]="$ISOFILES/loopback.cfg"
    ["/.disk/info"]="$ISOFILES/info"
)
for iso_path in "${!MAP[@]}"; do
    sum="$(md5sum "${MAP[$iso_path]}" | cut -d' ' -f1)"
    sed -i "s#^[0-9a-f]\{32\}  \.$iso_path\$#$sum  .$iso_path#" "$ISOFILES/md5sum.txt"
done
ARGS=()
for iso_path in "${!MAP[@]}"; do ARGS+=(-map "${MAP[$iso_path]}" "$iso_path"); done
ARGS+=(-map "$ISOFILES/md5sum.txt" /md5sum.txt)
rm -f "$ISO_OUT"
xorriso -indev "$ISO_IN" -outdev "$ISO_OUT" -boot_image any replay "${ARGS[@]}" 2>&1 | grep -vE '^xorriso : UPDATE' | tail -5
chown "${SUDO_USER:-root}:" "$ISO_OUT"
rm -rf "$WORK"
( cd "$OUTDIR" && sha256sum "$(basename "$ISO_OUT")" > "$(basename "$ISO_OUT").sha256" && chown "${SUDO_USER:-root}:" "$(basename "$ISO_OUT").sha256" )

say "Done"
ls -lh "$ISO_OUT"
cat "$ISO_OUT.sha256"
