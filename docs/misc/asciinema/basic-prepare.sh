#!/usr/bin/env bash
set -euo pipefail

sudo rm -r /media/backup/borgdemo || true
sudo mkdir -p /media/backup/borgdemo
sudo chown "$(whoami):$(whoami)" /media/backup/borgdemo
