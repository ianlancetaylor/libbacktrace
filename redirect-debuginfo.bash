#!/usr/bin/env bash

# libbacktrace hardcodes path to debug info. To run an executable using it,
# you may need this trick.
# This is not used in test, but to demontrate how to convince libbacktrace
# to use other debug info without root access.
# bash is required to use arrays in script.

# Usage example:
# - launch a bash with ./test.debug mounted:
# redirect-debuginfo.bash -p ./test.debug $(which bash)
# - launch ./test with ./test.debug (default directory) mounted:
# redirect-debuginfo.bash ./test


POSITIONAL_ARGS=()
debug_info_path=()
while [ $# -gt 0 ]; do
    case $1 in
        -h|--help) shift
            echo "Usage: $0 [OPTION]... [EXECUTABLE_PATH]..."
            echo "Run program with debug information mounted."
            echo
            echo "The xxx.debug file should have a xxx.build-id file containing"
            echo "build ID of program alongside." 
            echo
            echo "This is used to deal with programs using libbacktrace."
            echo "Requires fuse-overlayfs and bubblewrap."
            echo
            echo "-h, --help                display this help and exit"
            echo "-p, --debug-info-path     specify path to debug information"
            echo "                          can be given multiple times"
            echo "                          defaults to <EXECUTABLE_PATH>.debug"
            exit 0
            ;;
        -p|--debug-info-path) shift
            debug_info_path+=("$1"); shift
            ;;
        -*|--*)
            echo "Error: unknown option ($1)!"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1"); shift
            ;;
    esac
done
set -- "${POSITIONAL_ARGS[@]}"
if [ $# -gt 0 ]; then
    executable_path="$1"; shift
else
    echo "Error: missing argument <EXECUTABLE_PATH>!"
    exit 1
fi


if [ ! -d "/usr/lib/debug" ]; then
    echo "Error: /usr/lib/debug does not exist!"
    echo "You may fix this with: sudo mkdir -p /usr/lib/debug"
    exit 1
fi

if ! type fuse-overlayfs &> /dev/null; then
    echo "Error: command fuse-overlayfs is not found!"
    echo "You may fix this by installing fuse-overlayfs."
    exit 1
fi

if ! type bwrap &> /dev/null; then
    echo "Error: command bwrap is not found!"
    echo "You may fix this by installing bubblewrap."
    exit 1
fi

if [ ! -f $executable_path ]; then
    echo "Error: target executable ($executable_path) not present!"
    exit 1
fi
executable_path=$(readlink -f $executable_path)

if [ ${#debug_info_path[@]} -eq 0 ]; then
    debug_info_path+=("$(dirname $executable_path)/$(basename $executable_path).debug")
fi
build_id_as_dir=()
for position in ${!debug_info_path[@]}; do
    if [ ! -f ${debug_info_path[$position]} ]; then
        echo "Error: debug info (${debug_info_path[$position]}) not present!"
        exit 1
    fi
    debug_info_path[$position]=$(readlink -f ${debug_info_path[$position]})
    build_id_path="$(dirname ${debug_info_path[$position]})/$(basename -s .debug ${debug_info_path[$position]}).build-id"
    if [ ! -f $build_id_path ]; then
        echo "Error: missing build ID ($build_id_path) for debug info (${debug_info_path[$position]})!"
        exit 1
    fi
    build_id_as_dir+=("$(cut -c 1-2 $build_id_path)/$(cut -c 3- $build_id_path)")
done


tmp_dir=$(mktemp -d)
tmp_upper="$tmp_dir/upper"; mkdir $tmp_upper
tmp_work="$tmp_dir/work"; mkdir $tmp_work
tmp_merge="$tmp_dir/merge"; mkdir $tmp_merge

for position in ${!debug_info_path[@]}; do
    tmp_debug_path="$tmp_upper/.build-id/${build_id_as_dir[$position]}.debug"
    mkdir -p $(dirname $tmp_debug_path)
    ln -s ${debug_info_path[$position]} $tmp_debug_path
done

fuse-overlayfs -o lowerdir=/usr/lib/debug,upperdir=$tmp_upper,workdir=$tmp_work $tmp_merge

bwrap \
    --bind /home /home \
    --ro-bind /etc /etc \
    --ro-bind /usr /usr \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --symlink usr/sbin /sbin \
    --dir /tmp \
    --dir /var \
    --proc /proc \
    --dev /dev \
    --bind $tmp_merge /usr/lib/debug \
    $executable_path
exit_code=$?

fusermount -u $tmp_merge

rm -rf $tmp_dir

exit $exit_code
