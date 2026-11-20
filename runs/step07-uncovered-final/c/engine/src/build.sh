set -eu
for f in *.c; do /usr/bin/gcc -std=c17 -O0 -include decls.h -c "$f" -o "$f.o"; done
