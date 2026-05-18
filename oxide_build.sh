#!/usr/bin/env bash
set -euo pipefail

PROJECT="OXIDE Community Edition v8.3.1"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPLAY_FILE="$SRC_DIR/src/cli/display.rs"

# ── Tokyo Night palette ────────────────────────────────────────────────
TN_BG="40,  40,  40"
TN_FG="192, 202, 245"
TN_FG0="192, 202, 245"
TN_RED="247, 118, 142"
TN_RED_B="247, 118, 142"
TN_GRN="158, 206, 106"
TN_GRN_B="158, 206, 106"
TN_YLW="224, 175, 104"
TN_YLW_B="224, 175, 104"
TN_BLU="122, 162, 247"
TN_BLU_B="122, 162, 247"
TN_PUR="187, 154, 247"
TN_PUR_B="187, 154, 247"
TN_AQU="125, 207, 255"
TN_AQU_B="125, 207, 255"
TN_ORG="255, 158, 100"
TN_ORG_B="255, 158, 100"
TN_GRY="86,  95,  137"
TN_GRY_B="86,  95,  137"

# ── Gruvbox Dark palette (original) ──────────────────────────────────────
GB_BG="40,  40,  40"
GB_FG="235, 219, 178"
GB_FG0="251, 241, 199"
GB_RED="204, 36,  29"
GB_RED_B="251, 73,  52"
GB_GRN="152, 151, 26"
GB_GRN_B="184, 187, 38"
GB_YLW="215, 153, 33"
GB_YLW_B="250, 189, 47"
GB_BLU="69,  133, 136"
GB_BLU_B="131, 165, 152"
GB_PUR="177, 98,  134"
GB_PUR_B="211, 134, 155"
GB_AQU="104, 157, 106"
GB_AQU_B="142, 192, 124"
GB_ORG="214, 93,  14"
GB_ORG_B="254, 128, 25"
GB_GRY="146, 131, 116"
GB_GRY_B="168, 153, 132"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Themes:
  --tokyo-night    Apply Tokyo Night theme to display colors
  --revert-theme   Revert to original Gruvbox Dark + Rosé Pine

Database:
  --build-db      Rebuild encrypted SQLite DB from CSVs

Build:
  --release        Build in release mode (default: debug)
  --help           Show this help

Examples:
  $0                           debug build, gruvbox theme
  $0 --tokyo-night             debug build, tokyo night
  $0 --tokyo-night --release   release build, tokyo night
  $0 --build-db                rebuild encrypted DB only
EOF
}

TOKYO=false
REVERT=false
RELEASE=false
BUILD_DB=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tokyo-night)  TOKYO=true ;;
        --revert-theme) REVERT=true ;;
        --build-db)     BUILD_DB=true ;;
        --release)      RELEASE=true ;;
        --help)         usage; exit 0 ;;
        *) echo "Unknown: $1"; usage; exit 1 ;;
    esac
    shift
done

cd "$SRC_DIR"

if [[ "$BUILD_DB" == true ]]; then
    echo "[*] Rebuilding encrypted SQLite database from CSVs ..."
    python3 tools/build_db.py
    echo "[+] Done."
    exit 0
fi

cd "$SRC_DIR"

apply_theme() {
    local prefix="$1"
    shift
    while [[ $# -gt 0 ]]; do
        local name="$1" val="$2"
        local pad
        pad=$(printf '%*s' $((13 - ${#name})) '')
        sed -i "s/^pub const ${prefix}${name}:.*/pub const ${prefix}${name}:${pad} (u8, u8, u8) = (${val});/" "$DISPLAY_FILE"
        shift 2
    done
}

if [[ "$TOKYO" == true ]]; then
    echo "[*] Applying Tokyo Night theme ..."
    apply_theme "GB_" \
        BG    "$TN_BG"    FG    "$TN_FG"    FG0   "$TN_FG0" \
        RED   "$TN_RED"   RED_B "$TN_RED_B" \
        GRN   "$TN_GRN"   GRN_B "$TN_GRN_B" \
        YLW   "$TN_YLW"   YLW_B "$TN_YLW_B" \
        BLU   "$TN_BLU"   BLU_B "$TN_BLU_B" \
        PUR   "$TN_PUR"   PUR_B "$TN_PUR_B" \
        AQU   "$TN_AQU"   AQU_B "$TN_AQU_B" \
        ORG   "$TN_ORG"   ORG_B "$TN_ORG_B" \
        GRY   "$TN_GRY"   GRY_B "$TN_GRY_B"
    echo "[+] Tokyo Night applied."
    cargo check -j2 2>&1 | grep -E "^error" && { echo "[!] Compilation failed"; exit 1; } || echo "[+] Source OK."
fi

if [[ "$REVERT" == true ]]; then
    echo "[*] Reverting to Gruvbox Dark + Rosé Pine ..."
    apply_theme "GB_" \
        BG    "$GB_BG"    FG    "$GB_FG"    FG0   "$GB_FG0" \
        RED   "$GB_RED"   RED_B "$GB_RED_B" \
        GRN   "$GB_GRN"   GRN_B "$GB_GRN_B" \
        YLW   "$GB_YLW"   YLW_B "$GB_YLW_B" \
        BLU   "$GB_BLU"   BLU_B "$GB_BLU_B" \
        PUR   "$GB_PUR"   PUR_B "$GB_PUR_B" \
        AQU   "$GB_AQU"   AQU_B "$GB_AQU_B" \
        ORG   "$GB_ORG"   ORG_B "$GB_ORG_B" \
        GRY   "$GB_GRY"   GRY_B "$GB_GRY_B"
    echo "[+] Original theme restored."
    cargo check -j2 2>&1 | grep -E "^error" && { echo "[!] Compilation failed"; exit 1; } || echo "[+] Source OK."
fi

if [[ "$RELEASE" == true ]]; then
    echo "[*] Building $PROJECT in release mode ..."
    cargo build --release
    echo "[+] Binary: $SRC_DIR/target/release/oxide"
else
    echo "[*] Building $PROJECT in debug mode ..."
    cargo build
    echo "[+] Binary: $SRC_DIR/target/debug/oxide"
fi
