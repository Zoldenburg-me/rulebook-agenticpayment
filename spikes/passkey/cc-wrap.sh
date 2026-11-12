#!/bin/sh
# For assembly (.S) only: Apple clang 17 rejects blst 0.3.11's .cfi_* directives in
# portable mode. Preprocess, drop the .cfi_* (unwind-info only) lines, then assemble.
src=""; out=""; prev=""
for a in "$@"; do
  case "$a" in *.S) src="$a";; esac
  [ "$prev" = "-o" ] && out="$a"
  prev="$a"
done
[ -z "$src" ] && exec /usr/bin/cc "$@"
# Keep every flag except -o <out>, -c and the source, quoted (paths may contain spaces).
skip=0
for a in "$@"; do
  shift
  if [ $skip = 1 ]; then skip=0; continue; fi
  case "$a" in -o) skip=1;; -c|"$src") ;; *) set -- "$@" "$a";; esac
done
dir=$(mktemp -d -t blstasm) || exit 1
trap 'rm -rf "$dir"' EXIT
# Preprocess to a file first so a preprocessor failure is not masked by the pipe.
/usr/bin/cc "$@" -E "$src" -o "$dir/pp.s" || exit $?
grep -v -E '^[[:space:]]*\.cfi_' "$dir/pp.s" > "$dir/asm.s"
/usr/bin/cc "$@" -c -x assembler "$dir/asm.s" -o "$out"
