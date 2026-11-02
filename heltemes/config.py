"""Private local collector settings; never included in source control or exports."""
import json
import os
from pathlib import Path

from .sec import validate_user_agent


def user_agent(data_dir):
    override = os.environ.get('SEC_USER_AGENT', '').strip()
    if override:
        return override
    path = Path(data_dir).expanduser() / 'settings.json'
    if not path.exists():
        return ''
    if path.is_symlink() or path.stat().st_size > 4096:
        raise ValueError('Invalid local settings file.')
    data = json.loads(path.read_text(encoding='utf-8'))
    return data.get('sec_user_agent', '') if isinstance(data, dict) else ''


def configured(data_dir):
    try:
        validate_user_agent(user_agent(data_dir))
        return True
    except (OSError, ValueError):
        return False


def save_contact(data_dir, email):
    from .local_accounts import require_role
    require_role(data_dir, "collector")
    contact = validate_user_agent('HELTEMES Evidence/0.1 ' + email.strip())
    root = Path(data_dir).expanduser()
    if root.is_symlink():
        raise ValueError('Settings directory must not be a symbolic link.')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / 'settings.json'
    if path.is_symlink():
        raise ValueError('Settings file must not be a symbolic link.')
    # Exclude this file from backups: evidence recovery should not copy contact details.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        os.chmod(path, 0o600)
        json.dump({'sec_user_agent': contact}, handle)
        handle.write('\n')
    return path
