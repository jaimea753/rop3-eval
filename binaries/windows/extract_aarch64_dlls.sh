#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Must specify a wim file, e.g. /<windows iso>/sources/install.wim"
    exit 1
fi

out_dir=$(mktemp -d)

wimlib-imagex extract "$1" 1 \
    "Windows/System32/ntdll.dll" \
    "Windows/System32/kernel32.dll" \
    "Windows/System32/user32.dll" \
    "Windows/System32/gdi32.dll" \
    "Windows/System32/gdi32full.dll" \
    "Windows/System32/advapi32.dll" \
    "Windows/System32/rpcrt4.dll" \
    "Windows/System32/sechost.dll" \
    "Windows/System32/ucrtbase.dll" \
    "Windows/System32/win32u.dll" \
    "Windows/System32/msvcrt.dll" \
    "Windows/System32/ole32.dll" \
    "Windows/System32/oleaut32.dll" \
    "Windows/System32/shell32.dll" \
    "Windows/System32/shlwapi.dll" \
    "Windows/System32/ws2_32.dll" \
    "Windows/System32/combase.dll" \
    --dest-dir="$out_dir"

for dll in "$out_dir"/*.dll; do
    mv "$dll" ./"$(basename "$dll" .dll)_aarch64.dll"
done

rm -r "$out_dir"

