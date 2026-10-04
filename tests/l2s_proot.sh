# proot's link2symlink groups -- sourced by run_tests.sh (counters pass/fail/skip,
# $EMU, $AGCC and $A64_SCRATCH are its).
#
# What is under test (sys_file.c, "proot's link2symlink"; path.c, l2s_unhost): a
# rootfs installed through proot holds its hardlinks as proot writes them -- a
# symlink holding an absolute HOST path to an indirection symlink in the l2s
# directory, which names the data file, whose name ends in the live count. The
# emulator follows those, presents each name as the one regular file a hardlink
# is, and keeps proot's bookkeeping as names come and go.
#
# Two kinds of row, both against a layout this file lays down BY HAND, exactly as
# a device's proot wrote it (recorded on one: ".l2s.a0001" -> ".l2s.a0001.0002",
# member text <rootfs>/.l2s/.l2s.a0001):
#
#  1. DIFFERENTIAL, tests/fixtures/l2s_proot.c: the same program, run over real
#     hardlinks on a real kernel, printed tests/fixtures/l2s_proot.expect; the
#     emulator must print the same bytes over proot's layout. Then the host side:
#     the l2s directory must hold what proot itself would leave.
#  2. HOSTILE, tests/fixtures/l2s_probe.c: the symlinks of a rootfs are the
#     guest's -- or an image's -- to write. Layouts that claim to be groups they
#     are not, that point out of the rootfs, loop, sit over a read-only l2s
#     directory, or lean on the emulator's own scheme. What is asked: the
#     answers are an ordinary symlink's, and the CANARIES -- files outside the
#     rootfs, or on a read-only mount -- are byte-for-byte what they were.
#     A row that reads a host file or writes outside its rootfs is a hole.
#
# The scheme is compiled in only where the host needs it (Android) or with
# -DA64_LINK2SYMLINK (the android-sim build, which Makefile tells with
# A64_L2S_BUILD=1); under any other emulator these layouts are plain symlinks
# and there is nothing to ask.

l2sp_row() {   # l2sp_row <name> <expected> <got> [extra-failure-note]
    local name="$1" expect="$2" got="$3"
    if [ "$expect" = "$got" ]; then
        pass=$((pass+1)); echo "PASS l2s_proot: $name"
    else
        fail=$((fail+1)); echo "FAIL l2s_proot: $name"
        diff <(echo "$expect") <(echo "$got") | head -10 | sed 's/^/     /'
    fi
}

l2sp_verdict() {   # l2sp_verdict <name> <ok: 1|0> <what, on failure>
    if [ "$2" = 1 ]; then pass=$((pass+1)); echo "PASS l2s_proot: $1"
    else fail=$((fail+1)); echo "FAIL l2s_proot: $1 ($3)"; fi
}

# The rootfs W/r, a scratch directory of its own, the probe at /bin/p, and the
# host paths proot would have recorded: P (the rootfs), WP (its parent).
l2sp_newroot() {
    W=$(mktemp -d "$A64_SCRATCH/l2sp.XXXXXX") || return 1
    R=$W/r
    mkdir -p "$R/bin" "$R/.l2s" "$W/out" || return 1
    cp tests/fixtures/l2s_probe.bin "$R/bin/p" || return 1
    P=$(cd "$R" && pwd -P)
    WP=$(cd "$W" && pwd -P)
}

# A group the way proot makes it: <dir>/.l2s.<name>0001 -> <dirhost>/.l2s.<name>0001.<CCCC>.
l2sp_group() {   # l2sp_group <dir> <host path of that dir> <name> <count> <content>
    printf '%s' "$5" > "$1/.l2s.${3}0001.$(printf %04d "$4")"
    ln -s "$2/.l2s.${3}0001.$(printf %04d "$4")" "$1/.l2s.${3}0001"
}

# A tree's identity -- names, kinds, sizes, link texts, and every byte -- for the
# "was not touched" judgements.
l2sp_snap() {
    (cd "$1" && find . -printf '%p %y %s %l\n' | sort | md5sum | cut -c1-16
     find . -type f -print0 | sort -z | xargs -0 cat 2>/dev/null | md5sum | cut -c1-16)
}

l2sp_run() { timeout -k 5 60 "$EMU" --link2symlink "$@" 2>&1; }

# The groups the differential fixture works on (see l2s_proot.c).
l2sp_layout() {   # l2sp_layout <rootfs> <guest binary>
    local R="$1" bin="$2" P n
    P=$(cd "$R" && pwd -P)
    mkdir -p "$R/.l2s" "$R/g" "$R/h" "$R/bin2" "$R/bin"
    cp "$bin" "$R/bin/t"
    printf 'hello\n' > "$R/.l2s/.l2s.a0001.0003"
    ln -s "$P/.l2s/.l2s.a0001.0003" "$R/.l2s/.l2s.a0001"
    for n in g/a g/b h/c; do ln -s "$P/.l2s/.l2s.a0001" "$R/$n"; done
    printf 'plain\n' > "$R/g/plain"; printf 'p2\n' > "$R/h/p2"
    printf 'xx\n' > "$R/.l2s/.l2s.x10001.0002"
    ln -s "$P/.l2s/.l2s.x10001.0002" "$R/.l2s/.l2s.x10001"
    for n in x1 x2; do ln -s "$P/.l2s/.l2s.x10001" "$R/$n"; done
    cp "$bin" "$R/.l2s/.l2s.t10001.0002"; chmod 755 "$R/.l2s/.l2s.t10001.0002"
    ln -s "$P/.l2s/.l2s.t10001.0002" "$R/.l2s/.l2s.t10001"
    for n in bin2/t1 bin2/t2; do ln -s "$P/.l2s/.l2s.t10001" "$R/$n"; done
    chmod 644 "$R/.l2s/.l2s.a0001.0003" "$R/.l2s/.l2s.x10001.0002"
}

l2s_proot_suite() {
    local l2s_built=0
    [ "${A64_L2S_BUILD:-}" = 1 ] && l2s_built=1
    [ "$(uname -o 2>/dev/null)" = Android ] && l2s_built=1
    if [ "$l2s_built" != 1 ]; then
        skip=$((skip+1))
        echo "SKIP l2s_proot (this emulator carries no emulated-hardlink scheme: the android-sim build does)"
        return
    fi
    if [ ! -w "$A64_SCRATCH" ]; then
        skip=$((skip+1)); echo "SKIP l2s_proot (no writable scratch directory)"; return
    fi
    "$AGCC" -static -O2 -o tests/fixtures/l2s_proot.bin tests/fixtures/l2s_proot.c 2>/dev/null &&
    "$AGCC" -static -O2 -o tests/fixtures/l2s_probe.bin tests/fixtures/l2s_probe.c 2>/dev/null || {
        skip_build "fixtures/l2s_proot"; return; }
    local W R P WP got exp ok before out n m

    # ---- 1. the differential row, and the host's side of it ----
    W=$(mktemp -d "$A64_SCRATCH/l2sp.XXXXXX"); R=$W/r; mkdir -p "$R"
    l2sp_layout "$R" tests/fixtures/l2s_proot.bin
    P=$(cd "$R" && pwd -P)
    got=$(l2sp_run "$R" /bin/t proot)
    l2sp_row "the guest's view, over proot's layout, is a kernel's over real hardlinks" \
             "$(cat tests/fixtures/l2s_proot.expect)" "$got"
    # What proot would find afterwards: group a at count 2 (data renamed, the
    # indirection re-pointed), group x1 gone (its last name was removed), group
    # t1 untouched, no temporary left, and every member's text as it was.
    ok=1
    [ "$(ls -A "$R/.l2s" | tr '\n' ' ')" = ".l2s.a0001 .l2s.a0001.0002 .l2s.t10001 .l2s.t10001.0002 " ] || ok=0
    [ "$(readlink "$R/.l2s/.l2s.a0001")" = "$P/.l2s/.l2s.a0001.0002" ] || ok=0
    for n in x2 g/z; do [ "$(readlink "$R/$n")" = "$P/.l2s/.l2s.a0001" ] || ok=0; done
    for n in bin2/t1 bin2/t2; do [ "$(readlink "$R/$n")" = "$P/.l2s/.l2s.t10001" ] || ok=0; done
    [ "$(cat "$R/.l2s/.l2s.a0001.0002")" = hello ] || ok=0
    l2sp_verdict "the l2s directory is left as proot's own would leave it" "$ok" \
                 "$(ls -A "$R/.l2s" | tr '\n' ' ')"
    rm -rf "$W"
    # The same, with the rootfs named through a symlink: its recorded host path
    # is the real one, and the emulator must find it from either spelling.
    W=$(mktemp -d "$A64_SCRATCH/l2sp.XXXXXX"); mkdir -p "$W/real"
    l2sp_layout "$W/real" tests/fixtures/l2s_proot.bin; ln -s real "$W/via"
    got=$(l2sp_run "$W/via" /bin/t proot)
    l2sp_row "the rootfs named through a symlink" "$(cat tests/fixtures/l2s_proot.expect)" "$got"
    rm -rf "$W"

    # ---- 2. hostile layouts ----
    # A target that climbs out of the rootfs with ".." towards a VALID group
    # outside it. Resolved as a guest path, the climb stops at the root.
    l2sp_newroot; l2sp_group "$W/out" "$WP/out" k 2 $'SECRET\n'
    ln -s "$P/.l2s/../../out/.l2s.k0001" "$R/m"; before=$(l2sp_snap "$W/out")
    got=$(l2sp_run "$R" /bin/p lstat /m stat /m cat /m onf /m utime /m link /m /m2 lstat /m2 unlink /m unlink /m2)
    l2sp_row "a target climbing out with '..' reaches nothing" \
$'lstat /m: lnk nlink=1\nstat /m: errno=2\ncat /m: errno=2\nonf /m: failed errno=2\nutime /m: 0 errno=0\nlink /m2: 0 errno=0\nlstat /m2: lnk nlink=1\nunlink /m: 0 errno=0\nunlink /m2: 0 errno=0' "$got"
    l2sp_verdict "... and the group outside is untouched" "$([ "$before" = "$(l2sp_snap "$W/out")" ] && echo 1 || echo 0)" "canary changed"
    rm -rf "$W"
    # The host path of a SIBLING directory whose name merely starts with the
    # rootfs's own ("r" and "r2"): not under the rootfs, so not stripped. A
    # prefix match without the component boundary would strip "<rootfs>" and
    # leave "2/.l2s/...": so a REAL group is laid at /2/.l2s inside the rootfs,
    # the one place that wrongly stripped text would find one.
    l2sp_newroot; mkdir -p "$W/r2/.l2s" "$R/2/.l2s"; l2sp_group "$W/r2/.l2s" "$WP/r2/.l2s" k 2 $'SECRET\n'
    l2sp_group "$R/2/.l2s" "$P/2/.l2s" k 2 $'INSIDE\n'
    ln -s "$WP/r2/.l2s/.l2s.k0001" "$R/m"; before=$(l2sp_snap "$W/r2")
    got=$(l2sp_run "$R" /bin/p lstat /m cat /m link /m /m2 unlink /m unlink /m2)
    l2sp_row "a sibling directory that shares the rootfs's name as a prefix is not the rootfs" \
$'lstat /m: lnk nlink=1\ncat /m: errno=2\nlink /m2: 0 errno=0\nunlink /m: 0 errno=0\nunlink /m2: 0 errno=0' "$got"
    l2sp_verdict "... and that sibling is untouched" "$([ "$before" = "$(l2sp_snap "$W/r2")" ] && echo 1 || echo 0)" "canary changed"
    rm -rf "$W"
    # The host path of a VALID group outside the rootfs, spelled in full.
    l2sp_newroot; l2sp_group "$W/out" "$WP/out" k 2 $'SECRET\n'
    ln -s "$WP/out/.l2s.k0001" "$R/m"; before=$(l2sp_snap "$W/out")
    got=$(l2sp_run "$R" /bin/p lstat /m cat /m link /m /m2 unlink /m unlink /m2)
    l2sp_row "the host path of a valid group outside the rootfs reaches nothing" \
$'lstat /m: lnk nlink=1\ncat /m: errno=2\nlink /m2: 0 errno=0\nunlink /m: 0 errno=0\nunlink /m2: 0 errno=0' "$got"
    l2sp_verdict "... and the group outside is untouched" "$([ "$before" = "$(l2sp_snap "$W/out")" ] && echo 1 || echo 0)" "canary changed"
    rm -rf "$W"
    # An absolute host path that is NOT an l2s name keeps meaning what it always
    # did: re-rooted, so nothing there. Only the l2s form is reinterpreted.
    l2sp_newroot; mkdir "$R/etc"; echo real > "$R/etc/real"; ln -s "$P/etc/real" "$R/m"
    got=$(l2sp_run "$R" /bin/p lstat /m stat /m cat /m readlink /m | sed "s|$P|<R>|g")
    l2sp_row "a host-absolute symlink that is not an l2s name is left alone" \
$'lstat /m: lnk nlink=1\nstat /m: errno=2\ncat /m: errno=2\nreadlink /m: <R>/etc/real' "$got"
    rm -rf "$W"
    # Chains that do not check out are ordinary symlinks.
    l2sp_newroot
    ln -s "$P/.l2s/.l2s.n0001" "$R/m_noind"                                   # no indirection
    mkdir "$R/.l2s/.l2s.d0001.0002"; ln -s "$P/.l2s/.l2s.d0001.0002" "$R/.l2s/.l2s.d0001"
    ln -s "$P/.l2s/.l2s.d0001" "$R/m_dir"                                     # data is a directory
    mkdir "$R/other"; printf 'OTHER\n' > "$R/other/.l2s.o0001.0002"
    ln -s "$P/other/.l2s.o0001.0002" "$R/.l2s/.l2s.o0001"
    ln -s "$P/.l2s/.l2s.o0001" "$R/m_otherdir"                                # data in another directory
    printf 'ZZ\n' > "$R/.l2s/.l2s.zzzz0001.0002"
    ln -s "$P/.l2s/.l2s.zzzz0001.0002" "$R/.l2s/.l2s.q0001"
    ln -s "$P/.l2s/.l2s.q0001" "$R/m_mismatch"                                # data's name is not the indirection's
    printf 'FILE\n' > "$R/.l2s/.l2s.e0001"; ln -s "$P/.l2s/.l2s.e0001" "$R/m_notlink"   # indirection is a file
    got=""
    for m in m_noind m_dir m_otherdir m_mismatch m_notlink; do
        got="$got$(l2sp_run "$R" /bin/p lstat /$m stat /$m cat /$m | sed "s|$P|<R>|g")"$'\n'
    done
    l2sp_row "chains that do not check out are ordinary symlinks" \
$'lstat /m_noind: lnk nlink=1\nstat /m_noind: errno=2\ncat /m_noind: errno=2\nlstat /m_dir: lnk nlink=1\nstat /m_dir: dir nlink=0\ncat /m_dir: errno=21\nlstat /m_otherdir: lnk nlink=1\nstat /m_otherdir: reg nlink=1 size=6\ncat /m_otherdir: OTHER|\nlstat /m_mismatch: lnk nlink=1\nstat /m_mismatch: reg nlink=1 size=3\ncat /m_mismatch: ZZ|\nlstat /m_notlink: lnk nlink=1\nstat /m_notlink: reg nlink=1 size=5\ncat /m_notlink: FILE|\n' "$got"
    rm -rf "$W"
    # A loop: the data name is the indirection itself.
    l2sp_newroot
    ln -s "$P/.l2s/.l2s.c0001.0002" "$R/.l2s/.l2s.c0001"; ln -s "$P/.l2s/.l2s.c0001" "$R/.l2s/.l2s.c0001.0002"
    ln -s "$P/.l2s/.l2s.c0001" "$R/m"
    got=$(l2sp_run "$R" /bin/p lstat /m stat /m cat /m onf /m unlink /m)
    l2sp_row "a loop ends in ELOOP, not in a hang" \
$'lstat /m: lnk nlink=1\nstat /m: errno=40\ncat /m: errno=40\nonf /m: failed errno=40\nunlink /m: 0 errno=0' "$got"
    rm -rf "$W"
    # Counts at the ends: 0000 reads as one name (and the last unlink removes the
    # group); 9999 cannot take another (EMLINK) and is left as it was.
    l2sp_newroot
    l2sp_group "$R/.l2s" "$P/.l2s" f 0 $'F0\n'; ln -s "$P/.l2s/.l2s.f0001" "$R/m_zero"
    l2sp_group "$R/.l2s" "$P/.l2s" g 9999 $'G9\n'; ln -s "$P/.l2s/.l2s.g0001" "$R/m_max"
    got=$(l2sp_run "$R" /bin/p lstat /m_zero link /m_zero /m_zero2 lstat /m_zero2 unlink /m_zero unlink /m_zero2 lstat /m_max link /m_max /m_max2 lstat /m_max)
    l2sp_row "count 0000 is one name, count 9999 takes no more" \
$'lstat /m_zero: reg nlink=1 size=3\nlink /m_zero2: 0 errno=0\nlstat /m_zero2: reg nlink=2 size=3\nunlink /m_zero: 0 errno=0\nunlink /m_zero2: 0 errno=0\nlstat /m_max: reg nlink=9999 size=3\nlink /m_max2: -1 errno=31\nlstat /m_max: reg nlink=9999 size=3' "$got"
    ok=1; [ -z "$(ls -A "$R/.l2s" | grep '^\.l2s\.f0001')" ] || ok=0
    [ -e "$R/.l2s/.l2s.g0001.9999" ] || ok=0; [ ! -e "$R/m_max2" ] || ok=0
    l2sp_verdict "... the emptied group is gone, the full one is as it was" "$ok" "$(ls -A "$R/.l2s" | tr '\n' ' ')"
    rm -rf "$W"
    # The l2s directory on a READ-ONLY bind, the names in the writable rootfs: a
    # new name is EROFS (as a link onto a read-only mount), a stamp on the data
    # is EROFS, and a removed name still goes -- its count left alone, because
    # the count is a write into a mount the guest may not write.
    l2sp_newroot; rm -rf "$R/.l2s"; mkdir "$R/.l2s" "$W/ldir" "$R/g"
    l2sp_group "$W/ldir" "$P/.l2s" a 3 $'ROGROUP\n'; for n in x y z; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$n"; done
    echo hello > "$R/g/plain"; before=$(l2sp_snap "$W/ldir")
    got=$(l2sp_run -b "$WP/ldir:/.l2s:ro" "$R" /bin/p lstat /g/x cat /g/x link /g/x /g/new utime /g/x onf /g/x unlink /g/y rename /g/plain /g/z lstat /g/x)
    l2sp_row "the l2s directory on a read-only bind" \
$'lstat /g/x: reg nlink=3 size=8\ncat /g/x: ROGROUP|\nlink /g/new: -1 errno=30\nutime /g/x: -1 errno=30\nonf /g/x: ok errno=0\nunlink /g/y: 0 errno=0\nrename /g/z: 0 errno=0\nlstat /g/x: reg nlink=3 size=8' "$got"
    l2sp_verdict "... and the read-only directory is byte for byte what it was" "$([ "$before" = "$(l2sp_snap "$W/ldir")" ] && echo 1 || echo 0)" "written through a :ro bind"
    l2sp_verdict "... and no name was made" "$([ ! -L "$R/g/new" ] && [ -L "$R/g/x" ] && [ ! -L "$R/g/y" ] && echo 1 || echo 0)" "$(ls "$R/g" | tr '\n' ' ')"
    rm -rf "$W"
    # The same on a writable bind: the count follows the names.
    l2sp_newroot; rm -rf "$R/.l2s"; mkdir "$R/.l2s" "$W/ldir" "$R/g"
    l2sp_group "$W/ldir" "$P/.l2s" a 3 $'RWGROUP\n'; for n in x y z; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$n"; done
    got=$(l2sp_run -b "$WP/ldir:/.l2s" "$R" /bin/p lstat /g/x link /g/x /g/new lstat /g/x unlink /g/y unlink /g/z lstat /g/x)
    l2sp_row "the l2s directory on a writable bind" \
$'lstat /g/x: reg nlink=3 size=8\nlink /g/new: 0 errno=0\nlstat /g/x: reg nlink=4 size=8\nunlink /g/y: 0 errno=0\nunlink /g/z: 0 errno=0\nlstat /g/x: reg nlink=2 size=8' "$got"
    l2sp_verdict "... and the data file carries the count" "$([ -f "$W/ldir/.l2s.a0001.0002" ] && echo 1 || echo 0)" "$(ls -A "$W/ldir" | tr '\n' ' ')"
    rm -rf "$W"
    # The l2s directory is a symlink INSIDE the rootfs: resolved like any path.
    l2sp_newroot; rm -rf "$R/.l2s"; mkdir "$R/real"; ln -s real "$R/.l2s"
    l2sp_group "$R/real" "$P/.l2s" a 2 $'VIA-LINK\n'
    for n in m1 m2; do ln -s "$P/.l2s/.l2s.a0001" "$R/$n"; done
    got=$(l2sp_run "$R" /bin/p lstat /m1 cat /m1 link /m1 /m3 lstat /m1 unlink /m3 unlink /m2 lstat /m1)
    l2sp_row "the l2s directory is a symlink inside the rootfs" \
$'lstat /m1: reg nlink=2 size=9\ncat /m1: VIA-LINK|\nlink /m3: 0 errno=0\nlstat /m1: reg nlink=3 size=9\nunlink /m3: 0 errno=0\nunlink /m2: 0 errno=0\nlstat /m1: reg nlink=1 size=9' "$got"
    rm -rf "$W"
    # ... and a symlink to an absolute path OUTSIDE it, where the group is: the
    # absolute path is the guest's, re-rooted, so there is nothing there.
    l2sp_newroot; rm -rf "$R/.l2s"; l2sp_group "$W/out" "$WP/out" a 2 $'OUT\n'
    ln -s "$WP/out" "$R/.l2s"; ln -s "$P/.l2s/.l2s.a0001" "$R/m1"; before=$(l2sp_snap "$W/out")
    got=$(l2sp_run "$R" /bin/p lstat /m1 cat /m1 link /m1 /m2 unlink /m1 unlink /m2)
    l2sp_row "the l2s directory is a symlink to a host path outside" \
$'lstat /m1: lnk nlink=1\ncat /m1: errno=2\nlink /m2: 0 errno=0\nunlink /m1: 0 errno=0\nunlink /m2: 0 errno=0' "$got"
    l2sp_verdict "... and the group outside is untouched" "$([ "$before" = "$(l2sp_snap "$W/out")" ] && echo 1 || echo 0)" "canary changed"
    rm -rf "$W"
    # link(2) of a symlink names the SYMLINK a second time. The emulated-hardlink
    # fallback used to copy what it pointed at, and the host resolved that path
    # against ITS root: a symlink to /etc/hostname gave the guest the host's.
    l2sp_newroot; echo "OUTSIDE-SECRET" > "$W/out/secret.txt"
    ln -s "$WP/out/secret.txt" "$R/m"; ln -s /etc/hostname "$R/h"
    got=$(l2sp_run "$R" /bin/p link /m /m2 lstat /m2 cat /m2 link /h /h2 lstat /h2 cat /h2 readlink /h2)
    l2sp_row "link(2) of a symlink does not read the host" \
$'link /m2: 0 errno=0\nlstat /m2: lnk nlink=1\ncat /m2: errno=2\nlink /h2: 0 errno=0\nlstat /h2: lnk nlink=1\ncat /h2: errno=2\nreadlink /h2: /etc/hostname' "$got"
    rm -rf "$W"
    # The emulator's OWN scheme, hostile: the backing name is a symlink to a
    # host file. Moving a member out of its directory copies the backing, and
    # lstat reported its size and mode: both followed the host's resolution.
    l2sp_newroot; echo "HOSTONLY" > "$W/out/hostfile"
    ln -s "$WP/out/hostfile" "$R/.l2s.123"; : > "$R/.l2s.123.0002"; ln -s .l2s.123 "$R/x"; mkdir "$R/sub"
    got=$(l2sp_run "$R" /bin/p lstat /x cat /x rename /x /sub/y cat /sub/y lstat /sub/y)
    l2sp_row "the emulator's own scheme does not follow a backing symlink out" \
$'lstat /x: lnk nlink=1\ncat /x: errno=2\nrename /sub/y: -1 errno=40\ncat /sub/y: errno=2\nlstat /sub/y: errno=2' "$got"
    rm -rf "$W"
    # A process killed between the two renames of a count change leaves the data
    # file renamed and the indirection naming a file that is gone: the chain is
    # cut. Readers see an ordinary (dangling) symlink; the next change finds the
    # one data file there is, makes the chain whole, and goes on from its count.
    l2sp_newroot; mkdir "$R/g"; l2sp_group "$R/.l2s" "$P/.l2s" a 2 $'CUT\n'
    mv "$R/.l2s/.l2s.a0001.0002" "$R/.l2s/.l2s.a0001.0003"
    for n in x y; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$n"; done
    got=$(l2sp_run "$R" /bin/p lstat /g/x link /g/x /g/new lstat /g/x lstat /g/new)
    l2sp_row "a chain cut by a killed process is made whole by the next change" \
$'lstat /g/x: lnk nlink=1\nlink /g/new: 0 errno=0\nlstat /g/x: reg nlink=4 size=4\nlstat /g/new: reg nlink=4 size=4' "$got"
    l2sp_verdict "... leaving one data file and an indirection that names it" \
        "$([ "$(ls -A "$R/.l2s" | tr '\n' ' ')" = ".l2s.a0001 .l2s.a0001.0004 " ] && [ "$(readlink "$R/.l2s/.l2s.a0001")" = "$P/.l2s/.l2s.a0001.0004" ] && echo 1 || echo 0)" \
        "$(ls -A "$R/.l2s" | tr '\n' ' ')"
    rm -rf "$W"
    # Several processes adding and removing names of one group at once. The
    # count is a file's name and a change is two renames, so another process can
    # find the chain cut between them: a name added then must wait and not guess,
    # or it is a name nothing counted -- and the unlink of it a count nobody
    # raised, until the data is deleted from under the names that are left.
    ok=1; out=
    for n in 1 2 3; do
        l2sp_newroot; mkdir "$R/g"; l2sp_group "$R/.l2s" "$P/.l2s" a 2 $'STRESS\n'
        for m in x y; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$m"; done
        got=$(l2sp_run "$R" /bin/p stress /g/x 100 6 lstat /g/x lstat /g/y)
        [ "$got" = $'stress /g/x: 0 children failed\nlstat /g/x: reg nlink=2 size=7\nlstat /g/y: reg nlink=2 size=7' ] || { ok=0; out="$got"; }
        [ "$(ls -A "$R/.l2s" | tr '\n' ' ')" = ".l2s.a0001 .l2s.a0001.0002 " ] || { ok=0; out="$out $(ls -A "$R/.l2s" | tr '\n' ' ')"; }
        rm -rf "$W"
    done
    l2sp_verdict "six processes adding and removing names keep the count exact" "$ok" "$out"
}
