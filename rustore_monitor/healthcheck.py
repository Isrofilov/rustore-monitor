"""Проверка живости для Docker HEALTHCHECK: ``python -m rustore_monitor.healthcheck``.

Основной цикл после каждой итерации обновляет файл heartbeat. Если он
давно не менялся — цикл завис, контейнер помечается unhealthy.
Конфигурацию не импортирует, чтобы не зависеть от остальных переменных.
"""

import os
import sys
import time
from pathlib import Path


def main() -> int:
    heartbeat = Path(os.environ.get("DATA_DIR") or "/data") / "heartbeat"
    interval = int(os.environ.get("POLL_INTERVAL") or "300")
    # запас на долгую итерацию: много приложений, ретраи, паузы между сообщениями
    max_age = interval * 2 + 600
    try:
        age = time.time() - heartbeat.stat().st_mtime
    except FileNotFoundError:
        print(f"{heartbeat} ещё не создан")
        return 1
    if age > max_age:
        print(f"Последняя итерация {int(age)} с назад (допустимо {max_age} с)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
