#!/bin/sh

cmd=$(basename -- "$0")
config_dir=".build-service"
config_file="config.toml"

dir=$(pwd)
while :; do
    if [ -f "$dir/$config_dir/$config_file" ]; then
        build-cli "$cmd" "$@"
        exit_code=$?
        # Exit code 127 means connection failed and local_fallback is enabled
        # Fall through to execute local build tool
        if [ $exit_code -ne 127 ]; then
            exit $exit_code
        fi
        # If we get here, exit code was 127, fall back to local build
        break
    fi
    if [ "$dir" = "/" ]; then
        break
    fi
    dir=$(dirname -- "$dir")
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
old_ifs=$IFS
IFS=:
new_path=""
for entry in $PATH; do
    if [ "$entry" = "$script_dir" ]; then
        continue
    fi
    if [ -z "$new_path" ]; then
        new_path=$entry
    else
        new_path=$new_path:$entry
    fi
done
IFS=$old_ifs
if [ -z "$new_path" ]; then
    new_path="/usr/bin:/bin"
fi
PATH=$new_path exec "$cmd" "$@"
