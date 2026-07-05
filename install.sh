cat > install.sh << 'EOF'
#!/bin/bash
# DarkRecon — Dependency Installer
# Run: chmod +x install.sh && ./install.sh

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "██████╗  █████╗ ██████╗ ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗"
echo "██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗"
echo "██║  ██║███████║██████╔╝█████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗"
echo "██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║"
echo -e "${NC}Installing DarkRecon dependencies...\n"

# Check OS
OS="$(uname -s)"

# Python check
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Python3 not found. Please install Python 3.8+${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Python3 found: $(python3 --version)${NC}"

# pip check
if ! command -v pip3 &>/dev/null; then
    echo -e "${YELLOW}[!] pip3 not found — installing...${NC}"
    python3 -m ensurepip --upgrade
fi

# Install Python deps
pip3 install -r requirements.txt --break-system-packages -q
echo -e "${GREEN}[+] Python dependencies installed${NC}"

# Go tools
if command -v go &>/dev/null; then
    echo -e "\n${GREEN}[+] Go found — installing tools...${NC}"

    echo "  Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
    echo "  Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
    echo "  Installing gowitness..."
    go install github.com/sensepost/gowitness@latest 2>/dev/null
    echo "  Installing amass..."
    go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null

    echo -e "${GREEN}[+] Go tools installed${NC}"
else
    echo -e "\n${YELLOW}[!] Go not found — skipping subfinder/httpx/gowitness/amass${NC}"
    echo -e "    DarkRecon will use built-in Python fallbacks"
    echo -e "    Install Go: https://go.dev/dl/\n"
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo -e "Run: ${YELLOW}python3 recon.py -d example.com${NC}"
EOF

chmod +x install.sh
