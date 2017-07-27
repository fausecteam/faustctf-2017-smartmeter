#!/bin/bash
set -o pipefail

disass() {
    objdump -Mintel -d -j .text /tmp/bjnfc
}

wrong_check=$(disass | awk -F: '/esi,0x22$/ {gsub("^ +", "", $1) ; print($1)}')
echo "double quote character is checked at address 0x$wrong_check"

file_offset_hex=$(echo "$wrong_check" | cut -b 3-)
file_offset=$(printf "%d" "0x$file_offset_hex")
echo "address 0x$wrong_check is at file offset $file_offset"


if ! dd count=5 iflag=skip_bytes,count_bytes "skip=$file_offset" < /tmp/bjnfc 2>/dev/null | md5sum -c <(md5sum < sqli_orig.bin) > /dev/null ; then
    echo "did not find the \`mov esi, '\"'\` instruction at the expected file offset" >&2
    exit 1
fi

cp /tmp/bjnfc /tmp/bjnfc.no_sqli
nasm sqli_patched.s -o /dev/stdout | dd conv=notrunc oflag=seek_bytes seek="$file_offset" of=/tmp/bjnfc.no_sqli 2> /dev/null || echo "error during patching"

