#!/bin/zsh
set -eu
task_root=${0:A:h}
if [[ -e '/Library/HELTEMES Evidence' || -L '/Library/HELTEMES Evidence' ]]; then
  /usr/bin/sudo -- /Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -S -B '/Library/HELTEMES Evidence/app/scripts/local_operator.py' configure
else
  cd -- "$task_root"
  python3 -m heltemes configure
fi
printf '\nPress Enter to close this window. '
read -r
