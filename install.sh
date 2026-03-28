#!/usr/bin/env bash
# VK Cloud Whitelist IP Roller — установка на Ubuntu
# Использование: curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/vk-wlip-roller/main/install.sh | sudo bash
#            или: sudo bash install.sh
set -euo pipefail

REPO="${REPO_URL:-https://github.com/CAHEK2005/vk-wlip-roller}"
INSTALL_DIR="/opt/vk-wlip-roller"
SERVICE="vk-wlip-roller"

# Выбрать случайный свободный порт в диапазоне 8000-9999
_pick_port() {
  while true; do
    local p=$(shuf -i 8000-9999 -n 1 2>/dev/null || awk 'BEGIN{srand();print int(rand()*2000)+8000}')
    if ! ss -tuln 2>/dev/null | grep -q ":${p} " && \
       ! grep -q "PORT=${p}" /etc/systemd/system/${SERVICE}.service 2>/dev/null; then
      echo "$p"; return
    fi
  done
}
PORT=$([ -n "${PORT:-}" ] && echo "$PORT" || _pick_port)

echo "=== VK Cloud Whitelist IP Roller — установка ==="
echo "Репозиторий: $REPO"
echo "Директория:  $INSTALL_DIR"
echo ""

# Проверка прав
if [[ $EUID -ne 0 ]]; then
  echo "Запустите скрипт с правами root: sudo bash install.sh" >&2
  exit 1
fi

# Системные зависимости
echo "[1/5] Установка системных зависимостей..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv git curl

# Клонирование репозитория
echo "[2/5] Получение кода..."
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "  Обновление существующего репозитория..."
  git -C "$INSTALL_DIR" pull --quiet
else
  if [ -d "$INSTALL_DIR" ]; then
    echo "  Директория $INSTALL_DIR уже существует, но не является git-репозиторием."
    echo "  Удалите её вручную и запустите скрипт снова." >&2
    exit 1
  fi
  git clone --quiet "$REPO" "$INSTALL_DIR"
fi

# Виртуальное окружение
echo "[3/5] Создание виртуального окружения Python..."
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# systemd unit
echo "[4/5] Создание systemd сервиса..."
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=VK Cloud Whitelist IP Roller
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python app.py
Environment=PORT=$PORT
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Запуск
echo "[5/5] Запуск сервиса..."
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"

# Итог
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
echo ""
echo "============================================="
echo "  Установка завершена!"
echo "============================================="
echo ""
echo "  Веб-интерфейс:"
echo "    http://${LOCAL_IP}:${PORT}   (локальная сеть)"
echo "    http://127.0.0.1:${PORT}     (только этот хост)"
echo ""
echo "  Управление сервисом:"
echo "    systemctl status  $SERVICE"
echo "    systemctl stop    $SERVICE"
echo "    journalctl -u $SERVICE -f"
echo ""
echo "  Обновление:"
echo "    sudo bash $INSTALL_DIR/update.sh"
echo ""
# Сохранить порт для update.sh и повторного запуска
echo "$PORT" > "$INSTALL_DIR/.port"
echo "  Порт сохранён в $INSTALL_DIR/.port"
echo ""
