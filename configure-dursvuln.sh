#!/bin/bash
set -e

echo "-----------------------------------------------------"
echo "DursVulnNSE Global Installation and Configuration Script"
echo "-----------------------------------------------------"
echo "This script will help you install DursVulnNSE globally."
echo "It will copy necessary files to your Nmap directory and adjust paths."
echo "Please ensure you have sudo privileges."
echo ""

# Function to copy files with debug output
copy_with_debug() {
    local src=$1
    local dest=$2
    echo "  - Copying '$src' to '$dest'..."
    if sudo cp -r "$src" "$dest"; then
        echo "    ...Success."
    else
        echo "    ...ERROR: Failed to copy '$src'. Exiting."
        exit 1
    fi
}

# Determine Nmap data directory
NMAP_DATA_DIR=""
echo "Please choose your Nmap data directory:"
echo "1) /usr/local/share/nmap (Common for manual installations)"
echo "2) /usr/share/nmap (Common for package manager installations)"
read -p "Enter your choice (1 or 2): " choice

case $choice in
    1)
        NMAP_DATA_DIR="/usr/local/share/nmap"
        ;;
    2)
        NMAP_DATA_DIR="/usr/share/nmap"
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

NMAP_SCRIPTS_DIR="$NMAP_DATA_DIR/scripts"
NMAP_NSELIB_DIR="$NMAP_DATA_DIR/nselib"
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )" 

echo ""
echo "Selected Nmap data directory: $NMAP_DATA_DIR"
echo "Nmap scripts directory: $NMAP_SCRIPTS_DIR"
echo "Nmap libraries directory: $NMAP_NSELIB_DIR"
echo ""

echo "--- Step 1: Copying Project Files to Nmap Directory ---"
sudo mkdir -p "$NMAP_NSELIB_DIR" || { echo "Failed to create Nmap nselib directory. Exiting."; exit 1; }
copy_with_debug "$PROJECT_ROOT/dursvuln.nse" "$NMAP_SCRIPTS_DIR/"
copy_with_debug "$PROJECT_ROOT/dursvuln/lib/dkjson.lua" "$NMAP_NSELIB_DIR/"
copy_with_debug "$PROJECT_ROOT/dursvuln/lib/vulndb.lua" "$NMAP_NSELIB_DIR/"
copy_with_debug "$PROJECT_ROOT/database" "$NMAP_NSELIB_DIR/"
echo "Files copied successfully."

echo ""
echo "--- Step 2: Adjusting Paths in Copied Scripts ---"
# Remove local package.path adjustment from dursvuln.nse (if it exists)
sudo sed -i "/package\.path = \".\/dursvuln\/lib\/\?.lua;\" \.\. package\.path/d" "$NMAP_SCRIPTS_DIR/dursvuln.nse" 2>/dev/null || true
echo "Local package.path removed from dursvuln.nse (if present)."

# Adjust path in vulndb.lua for cve-main.json
sudo sed -i "s|local db_path = db_path_arg or \"database\/cve-main\.json\"|local db_path = db_path_arg or \"$NMAP_NSELIB_DIR\/database\/cve-main\.json\"|g" "$NMAP_NSELIB_DIR/vulndb.lua" || { echo "Failed to adjust cve-main.json path in vulndb.lua. Exiting."; exit 1; }
echo "cve-main.json path adjusted in vulndb.lua."

# Adjust path in vulndb.lua for product.json
sudo sed -i "s|local config_path = \"database\/product\.json\"|local config_path = \"$NMAP_NSELIB_DIR\/database\/product\.json\"|g" "$NMAP_NSELIB_DIR/vulndb.lua" || { echo "Failed to adjust product.json path in vulndb.lua. Exiting."; exit 1; }
echo "product.json path adjusted in vulndb.lua."

echo ""
echo "--- Step 3: Updating Nmap Script Database ---"
sudo nmap --script-updatedb || { echo "Failed to update Nmap script database. Exiting."; exit 1; }
echo "Nmap script database updated successfully."

echo ""
echo "-----------------------------------------------------"
echo "DursVulnNSE Global Installation Complete!"
echo "You can now run Nmap with --script=dursvuln from any location."
echo "-----------------------------------------------------"
