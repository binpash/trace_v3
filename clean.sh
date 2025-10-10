#!/bin/bash
# clean_folders.sh
# Removes 'git' and 'temp' folders if present in the current directory.

for dir in git temp; do
    if [ -d "$dir" ]; then
        echo "Removing directory: $dir"
        rm -rf "$dir"
    else
        echo "No such directory: $dir"
    fi
done
