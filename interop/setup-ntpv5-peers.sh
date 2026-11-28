#!/bin/sh
#
# Builds the two NTPv5 peers of the interop lane from source, at the commits that implement
# draft-ietf-ntp-ntpv5-10, into /opt/ntpv5-interop (or $NTPV5_PEERS):
#
#   chrony-ntp5  https://github.com/mlichvar/chrony-ntp5  chronyd and chronyc, NTPv5 and NTS
#   ntp5-exp     https://github.com/mlichvar/ntp5-exp     ntpnode.py, an NTPv5+NTPv4 client and server
#
# Both are by the draft's author and are the implementations its § 14 lists. Neither is
# packaged anywhere, so they are built here. Run as root - inside WSL on Windows:
#
#   wsl -u root sh interop/setup-ntpv5-peers.sh
#
# Pinned rather than taken from the branch heads: the suite is pinned to draft -10, and a peer
# that moved on to -11 would answer it with silence (§ 7.1), which looks like a failure of
# Norn's. Move the pins together with the draft.

set -eu

PREFIX="${NTPV5_PEERS:-/opt/ntpv5-interop}"

CHRONY_NTP5_URL="https://github.com/mlichvar/chrony-ntp5.git"
CHRONY_NTP5_COMMIT="4233f428650fdc4a5bb04027c6de7b9a81da6bcb"    # "ntp: update draft ID to draft-ietf-ntp-ntpv5-10"

NTP5_EXP_URL="https://github.com/mlichvar/ntp5-exp.git"
NTP5_EXP_COMMIT="0e3056e43b7e486ecb7ed2031b7f02f701658a2d"       # "update draft ID to draft-ietf-ntp-ntpv5-10"

if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git gcc make bison pkg-config \
        libgnutls28-dev nettle-dev libcap-dev python3 >/dev/null
fi

mkdir -p "$PREFIX/src"

fetch() {    # url commit directory
    if [ ! -d "$3/.git" ]; then
        git clone -q "$1" "$3"
    fi
    git -C "$3" fetch -q origin
    git -C "$3" checkout -q --detach "$2"
}

fetch "$CHRONY_NTP5_URL" "$CHRONY_NTP5_COMMIT" "$PREFIX/src/chrony-ntp5"
fetch "$NTP5_EXP_URL"    "$NTP5_EXP_COMMIT"    "$PREFIX/src/ntp5-exp"

# chrony-ntp5: without seccomp and readline, which the tests need neither of; the man pages
# need asciidoctor, so only the two programs are installed.
cd "$PREFIX/src/chrony-ntp5"
./configure --prefix="$PREFIX/chrony-ntp5" --without-seccomp --disable-readline > "$PREFIX/chrony-ntp5-configure.log" 2>&1
make -j"$(nproc)" > "$PREFIX/chrony-ntp5-make.log" 2>&1
mkdir -p "$PREFIX/chrony-ntp5/sbin" "$PREFIX/chrony-ntp5/bin"
install -m 755 chronyd "$PREFIX/chrony-ntp5/sbin/chronyd"
install -m 755 chronyc "$PREFIX/chrony-ntp5/bin/chronyc"

# ntp5-exp: Python, nothing to build.
mkdir -p "$PREFIX/ntp5-exp"
install -m 755 "$PREFIX/src/ntp5-exp/ntpnode.py" "$PREFIX/ntp5-exp/ntpnode.py"

"$PREFIX/chrony-ntp5/sbin/chronyd" --version
python3 "$PREFIX/ntp5-exp/ntpnode.py" --help | head -1
echo "NTPv5 peers installed in $PREFIX"
