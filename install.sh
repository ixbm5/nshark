#!/usr/bin/env bash
set -e

echo ""
echo "  ███╗   ██╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗"
echo "  ████╗  ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝"
echo "  ██╔██╗ ██║███████╗███████║███████║██████╔╝█████╔╝ "
echo "  ██║╚██╗██║╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ "
echo "  ██║ ╚████║███████║██║  ██║██║  ██║██║  ██║██║  ██╗"
echo "  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝"
echo "                   INSTALLER"
echo ""

# 1. Verify python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: python3 is required but not installed."
    exit 1
fi

echo "[*] Setting up NSHARK isolated environment in ~/.nshark/venv..."
INSTALL_DIR="$HOME/.nshark/venv"
mkdir -p "$HOME/.nshark"
python3 -m venv "$INSTALL_DIR"

echo "[*] Installing NSHARK and dependencies..."
"$INSTALL_DIR/bin/python3" -m pip install --upgrade pip --quiet

if [ -f "pyproject.toml" ]; then
    "$INSTALL_DIR/bin/pip" install . --quiet
else
    "$INSTALL_DIR/bin/pip" install "git+https://github.com/ixbm5/nshark.git" --quiet
fi

# 2. Link binary into ~/.local/bin
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/bin/nshark" "$BIN_DIR/nshark"

# If /usr/local/bin is writable, link there too for instant access
if [ -w "/usr/local/bin" ]; then
    ln -sf "$INSTALL_DIR/bin/nshark" "/usr/local/bin/nshark" 2>/dev/null || true
fi

# 3. Ensure ~/.local/bin is in PATH for future terminal sessions
for RC_FILE in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -f "$RC_FILE" ] || [ "$(basename "$SHELL")" = "$(basename "${RC_FILE%.*}")" ]; then
        if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$RC_FILE" 2>/dev/null; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC_FILE"
        fi
    fi
done

echo ""
echo "[+] NSHARK successfully installed!"
echo "[*] Try running: nshark --help"
echo ""
