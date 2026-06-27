#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/joe/BCM2153}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/home/joe/thing}"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra_12.1_PUBLIC}"

PROJECT_ROOT="${PROJECT_ROOT:-$REPO_DIR/out/ghidra}"
PROJECT_DIR="$PROJECT_ROOT/projects"
LOG_DIR="$PROJECT_ROOT/logs"
SCRIPT_DIR="$REPO_DIR/tools/ghidra_scripts"
PROJECT_NAME="${PROJECT_NAME:-BCM2153}"

ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"
PROCESSOR="${PROCESSOR:-ARM:LE:32:v5t}"
CSPEC="${CSPEC:-default}"

mkdir -p "$PROJECT_DIR" "$LOG_DIR"

if [[ ! -x "$ANALYZE" ]]; then
  echo "Missing analyzeHeadless: $ANALYZE" >&2
  exit 1
fi

for image in amss.bin bcmboot.img; do
  if [[ ! -f "$FIRMWARE_DIR/$image" ]]; then
    echo "Missing firmware sample: $FIRMWARE_DIR/$image" >&2
    exit 1
  fi
done

run_import() {
  local name="$1"
  local path="$2"
  local base="$3"
  local offset="$4"
  local length="$5"

  "$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME"     -import "$path"     -overwrite     -processor "$PROCESSOR"     -cspec "$CSPEC"     -loader BinaryLoader     -loader-blockName "$name"     -loader-baseAddr "$base"     -loader-fileOffset "$offset"     -loader-length "$length"     -scriptPath "$SCRIPT_DIR"     -postScript AnnotateBcm2153.java "$name" "$base" "$offset"     -log "$LOG_DIR/$name.log"     -scriptlog "$LOG_DIR/$name.script.log"
}

run_import "amss_80300000"   "$FIRMWARE_DIR/amss.bin"   "0x80300000"   "0x0"   "0x58e2a4"

run_import "bcmboot_28000000_from_0x40"   "$FIRMWARE_DIR/bcmboot.img"   "0x28000000"   "0x40"   "0xab26"

cat <<EOF
Ghidra project written under:
  $PROJECT_DIR/$PROJECT_NAME.gpr

Logs:
  $LOG_DIR
EOF
