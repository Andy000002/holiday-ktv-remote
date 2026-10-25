#!/bin/bash
# 上傳到部署主機並重建容器（主機上的 data/ 與 .env 不會被覆蓋）
# 部署目標寫在 .deploy.env：DEPLOY_HOST=user@host、DEPLOY_DIR=遠端資料夾
set -e
cd "$(dirname "$0")"
source .deploy.env
tar --exclude=data --exclude=__pycache__ --exclude=.env --exclude=.deploy.env --exclude=notes --exclude=.git -cf - . | \
  ssh "$DEPLOY_HOST" "cd $DEPLOY_DIR && tar -xf - && export PATH=/usr/local/bin:/opt/homebrew/bin:\$PATH && docker compose up -d --build 2>&1 | tail -2"
