#!/usr/bin/env bash
# VK Cloud Whitelist IP Roller — обновление до последней версии
# Использование: sudo bash /opt/vk-wlip-roller/update.sh
set -euo pipefail

INSTALL_DIR="/opt/vk-wlip-roller"
SERVICE="vk-wlip-roller"

if [[ $EUID -ne 0 ]]; then
  echo "Запустите скрипт с правами root: sudo bash update.sh" >&2
  exit 1
fi

if [ ! -d "$INSTALL_DIR/.git" ]; then
  echo "Репозиторий не найден в $INSTALL_DIR. Сначала запустите install.sh." >&2
  exit 1
fi

echo "=== Обновление VK Cloud Whitelist IP Roller ==="

echo "[1/3] Получение обновлений из репозитория..."
git -C "$INSTALL_DIR" pull

echo "[2/3] Обновление Python зависимостей..."
"$INSTALL_DIR/.venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

echo "[3/3] Перезапуск сервиса..."
systemctl restart "$SERVICE"

echo ""
echo "=== Обновление завершено ==="
echo "Версия: $(git -C "$INSTALL_DIR" log -1 --format='%h %s (%ci)')"
echo "Логи:   journalctl -u $SERVICE -f"
echo ""
