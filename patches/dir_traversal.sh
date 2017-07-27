#!/bin/bash
set -o pipefail

disass() {
    objdump -Mintel -d -j .text /tmp/bjnfc
}

strstr_call=$(disass | awk -F: '/strstr@plt>$/ {gsub("^ +", "", $1) ; print($1)}')
echo "strstr is called from address 0x$strstr_call"

strstr_line=$(disass | awk -F: "/^ *$strstr_call/ {print NR}")

arg1_addr=$(disass | head "-n+$strstr_line" | tail -n 6 | awk -F: '/rdi/ { gsub("^ +", "", $1); print $1 }')
echo "arg1 for strstr is set at address 0x$strstr_call"
file_offset_hex=$(echo "$arg1_addr" | cut -b 3-)
file_offset=$(printf "%d" "0x$file_offset_hex")
echo "address 0x$strstr_call is at file offset $file_offset"



if ! dd count=10 iflag=skip_bytes,count_bytes skip="$file_offset" < /tmp/bjnfc 2>/dev/null | md5sum -c <(md5sum < dir_trav_orig.bin) > /dev/null ; then
    echo "did not find expected arguments for strstr call!" >&2
    xxd -s "$file_offset" -len 10 < /tmp/bjnfc
    exit 1
fi

cp /tmp/bjnfc /tmp/bjnfc.no_dir_trav
nasm dir_trav_patched.s -o /dev/stdout | dd conv=notrunc oflag=seek_bytes seek="$file_offset" of=/tmp/bjnfc.no_dir_trav 2> /dev/null || echo "error during patching"

