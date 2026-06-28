#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/joe/BCM2153}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/home/joe/thing}"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra_12.1_PUBLIC}"
PROJECT_ROOT="${PROJECT_ROOT:-$REPO_DIR/out/ghidra_shpapp}"
PROJECT_DIR="$PROJECT_ROOT/projects"
LOG_DIR="$PROJECT_ROOT/logs"
WORK_DIR="$PROJECT_ROOT/work"
PROJECT_NAME="${PROJECT_NAME:-BCM2153_ShpApp}"
ELF_OFFSET="${ELF_OFFSET:-0x192e}"
RUN_ANALYSIS="${RUN_ANALYSIS:-0}"

ANALYZE="$GHIDRA_HOME/support/analyzeHeadless"
INPUT="$FIRMWARE_DIR/ShpApp.app"
ELF_PATH="$WORK_DIR/ShpApp_embedded.elf"

mkdir -p "$PROJECT_DIR" "$LOG_DIR" "$WORK_DIR"

if [[ ! -x "$ANALYZE" ]]; then
  echo "Missing analyzeHeadless: $ANALYZE" >&2
  exit 1
fi

if [[ ! -f "$INPUT" ]]; then
  echo "Missing firmware sample: $INPUT" >&2
  exit 1
fi

python3 - "$INPUT" "$ELF_PATH" "$ELF_OFFSET" <<'PYEXTRACT'
from pathlib import Path
import sys

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
offset = int(sys.argv[3], 0)
data = src.read_bytes()
if data[offset:offset + 4] != b"\x7fELF":
    raise SystemExit(f"ELF magic not found at {offset:#x} in {src}")
dst.write_bytes(data[offset:])
print(f"Wrote {dst} from {src.name} offset {offset:#x}")
PYEXTRACT

ANALYSIS_ARGS=()
if [[ "$RUN_ANALYSIS" != "1" ]]; then
  ANALYSIS_ARGS=(-noanalysis)
fi

"$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME" \
  -import "$ELF_PATH" \
  -overwrite \
  "${ANALYSIS_ARGS[@]}" \
  -log "$LOG_DIR/ShpApp_embedded_elf.log" \
  -scriptlog "$LOG_DIR/ShpApp_embedded_elf.script.log"

cat <<EOF
ShpApp Ghidra project written under:
  $PROJECT_DIR/$PROJECT_NAME.gpr

Extracted local ELF copy:
  $ELF_PATH

Logs:
  $LOG_DIR

Automatic analysis:
  $RUN_ANALYSIS (set RUN_ANALYSIS=1 to enable)
EOF
