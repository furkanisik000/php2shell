#!/usr/bin/env bash
# #3 CoreGuard build C = 8.4.27 + linux/coreguard/patches/*.patch (plan §13.5
# separation): the official source (sources/php-8.4.27) is never edited; the
# experiment copy ext/coreguard-src-8.4.27 is a clone of it, reset to the
# same commit and patched from the committed patch files on every build.
# Flavors: asanext (safety evaluation) / normalext (performance, PHPT) /
# ztsnormalext (normalext + ZTS, CG-3 NTS/ZTS verification) - the same
# configure options as linux/build.sh so B and C differ only by the patch.
# Usage: build-coreguard.sh [asanext|normalext|ztsnormalext]
set -euo pipefail
flavor=${1:-asanext}
[[ "$flavor" = asanext || "$flavor" = normalext || "$flavor" = ztsnormalext ]] || exit 2
version=8.4.27
base=/home/phplab/php-lab
repo=/mnt/c/Users/user/Downloads/php
official=$base/sources/php-$version
copy=$base/ext/coreguard-src-$version
build=$base/builds/$version-coreguard-$flavor
prefix=$base/install/$version-coreguard-$flavor
mkdir -p "$base/ext" "$base/builds" "$base/install" "$base/logs"
exec > >(tee "$base/logs/build-$version-coreguard-$flavor.log") 2>&1
g() { git -c safe.directory='*' "$@"; }
test -z "$(g -C "$official" status --porcelain)" || { echo 'official source modified; refusing'; exit 1; }
commit=$(g -C "$official" rev-parse HEAD)
[ -d "$copy/.git" ] || g clone -q --depth 1 "file://$official" "$copy"
g -C "$copy" checkout -q --detach "$commit"
g -C "$copy" reset -q --hard "$commit"
# tracked files only: untracked buildconf outputs (configure) are kept, the
# build itself is out of tree
patches=("$repo"/linux/coreguard/patches/*.patch)
for p in "${patches[@]}"; do g -C "$copy" apply --whitespace=nowarn "$p"; echo "applied $(basename "$p")"; done
if [ ! -f "$copy/configure" ]; then ( cd "$copy"; ./buildconf --force ); fi
ext_options=(--enable-opcache --with-libxml --enable-soap --enable-xml --enable-simplexml --enable-dom
             --enable-xmlreader --enable-xmlwriter --enable-filter --enable-exif
             --enable-mbstring --disable-mbregex)
options=(--disable-all --enable-cli --enable-fpm --enable-session --without-pear --prefix="$prefix"
         "${ext_options[@]}")
if [ "$flavor" = asanext ]; then
  flags=(-g3 -O1 -fno-omit-frame-pointer)
  options+=(--enable-debug --enable-address-sanitizer)
else
  flags=(-g3 -O2 -fno-omit-frame-pointer)
  options+=(--disable-debug)
  if [ "$flavor" = ztsnormalext ]; then options+=(--enable-zts); fi
fi
rm -rf "$build"; mkdir -p "$build"; cd "$build"
CC=clang CXX=clang++ CFLAGS="${flags[*]}" CXXFLAGS="${flags[*]}" "$copy/configure" "${options[@]}"
make -j2
make install
"$prefix/bin/php" -n -v
python3 - "$version" "coreguard-$flavor" "$commit" "$prefix" "${options[*]}" "${patches[@]}" <<'PY'
import hashlib, json, pathlib, subprocess, sys
sys.path.insert(0, '/mnt/c/Users/user/Downloads/php/linux')
import provenance
version, flavor, commit, prefix, configure, *patches = sys.argv[1:]
data = dict(version=version, flavor=flavor, source_commit=commit, prefix=prefix,
            configure=configure, experiment_copy='ext/coreguard-src-' + version,
            patches={pathlib.Path(p).name: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
                     for p in patches},
            compiler=subprocess.check_output(['clang', '--version'], text=True).splitlines()[0])
data['binary_sha256'] = {name: hashlib.sha256(pathlib.Path(prefix, name).read_bytes()).hexdigest()
                         for name in ('bin/php', 'sbin/php-fpm')}
data['repo_provenance'] = provenance.provenance()
pathlib.Path(prefix, 'build-manifest.json').write_text(json.dumps(data, indent=2))
print(json.dumps(dict(prefix=prefix, patches=data['patches'],
                      citable=data['repo_provenance']['citable']), indent=2))
PY
