#!/usr/bin/env bash
if ! command -v inkscape &> /dev/null; then
  echo "inkscape not found, please install: pacman -Sy inkscape"
  exit
fi

PROJ_PATH="$(realpath "$(dirname "$0")/../")"
inkscape "$PROJ_PATH/icon.svg" -o "$PROJ_PATH/icon.png"
