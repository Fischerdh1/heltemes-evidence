#!/bin/zsh
set -u
task_root=${0:A:h}
task_python=/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14
"$task_python" -I -S -B "$task_root/scripts/run_recovery_workflow.py"
task_result=$?
printf '\nPress Enter to close this window. '
read -r
exit "$task_result"
