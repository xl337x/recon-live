#!/usr/bin/env bash
# Install every recon-live dependency on Kali / Debian / WSL and fix PATH.
# Safe to re-run: already-installed tools are skipped by the installers.
set +e
echo "[*] recon-live setup — installing the full toolchain…"

# GOSUMDB=off avoids the transient sum.golang.org HTTP/2 errors we hit before.
export GOSUMDB=off GOFLAGS=-mod=mod
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"

if ! command -v go >/dev/null 2>&1; then
  echo "[!] go not found — installing golang…"
  command -v apt-get >/dev/null 2>&1 && sudo apt-get update -y && sudo apt-get install -y golang-go
fi

# ---- go tools (no sudo). httpx MUST be the ProjectDiscovery one, not python httpx ----
if command -v go >/dev/null 2>&1; then
  declare -A GOTOOLS=(
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [gau]="github.com/lc/gau/v2/cmd/gau@latest"
    [assetfinder]="github.com/tomnomnom/assetfinder@latest"
    [waybackurls]="github.com/tomnomnom/waybackurls@latest"
    [dalfox]="github.com/hahwul/dalfox/v2@latest"
    [subzy]="github.com/PentestPad/subzy@latest"
  )
  for name in "${!GOTOOLS[@]}"; do
    if [ -x "$HOME/go/bin/$name" ]; then
      echo "[=] $name already present"
    else
      echo "[+] go install $name…"
      go install "${GOTOOLS[$name]}" && echo "    ok" || echo "    FAILED ($name)"
    fi
  done
fi

# ---- apt tools (need sudo): feroxbuster + chromium (screenshots) + seclists (wordlists) ----
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y feroxbuster chromium seclists 2>/dev/null
fi

# ---- nuclei templates (auto-downloaded on first run too) ----
command -v nuclei >/dev/null 2>&1 && nuclei -update-templates 2>/dev/null

# ---- persist PATH for future shells ----
LINE='export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin"'
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  grep -q 'go/bin' "$rc" || echo "$LINE" >> "$rc"
done

echo "[+] setup done. Run:  python3 recon-live.py <domain>"
