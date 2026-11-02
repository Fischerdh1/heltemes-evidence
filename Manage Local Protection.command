#!/bin/zsh
set -eu
task_root=${0:A:h}
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -S -B "$task_root/scripts/control_local_accounts.py"
printf '\nPress Enter to close this window. '
read -r
