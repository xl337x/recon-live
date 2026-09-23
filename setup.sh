#!/usr/bin/env bash
# Install recon-live's tool dependencies on Kali / Debian / WSL and fix PATH.
set +e
echo "[*] installing recon toolchain…"

# ProjectDiscovery + tomnomnom tools via go (httpx MUST be the PD one, not python httpx)
if command -v go >/dev/null 2>&1; then
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/tomnomnom/assetfinder@latest
else
  echo "[!] go not found — install golang first (apt-get install -y golang-go)"
fi

# apt-provided tools (Kali has most of these)
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y subfinder dnsx feroxbuster nuclei 2>/dev/null
fi

# optional: nuclei fuzzing templates for the intel/-dast stage
command -v nuclei >/dev/null 2>&1 && nuclei -update-templates 2>/dev/null

# PATH: go / pipx / cargo bin dirs
LINE='export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"'
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  grep -q 'go/bin' "$rc" || echo "$LINE" >> "$rc"
done

echo "[+] done. Open a new shell (PATH updated), then: python3 recon-live.py"
