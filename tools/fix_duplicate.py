"""
fix_duplicate.py

Author : Kang Ali

This script provides a utility to clean the main CVE (Common Vulnerabilities and Exposures)
database file (`cve-main.json`) by removing duplicate entries. It is designed to be used
when manual additions or other processes might introduce redundant CVE entries, ensuring
that each CVE ID appears only once in the database.

Usage:
    Run this script directly to clean the main CVE database:
    
    python3 tools/fix_duplicate.py
"""

import json
import os

# Define base directories for script, project root, and database.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
DATABASE_DIR = os.path.join(PROJECT_ROOT, "database")

# Define the path to the main CVE database file.
DATABASE_FILE: str = os.path.join(DATABASE_DIR, 'cve-main.json')

def fix_duplicates_in_cve_db():
    """
    Reads the main CVE database file, identifies and removes duplicate entries
    based on the 'id' field, and then writes the unique entries back to the file.
    The output format is a JSON array where each CVE object is on a single line.
    """
    print(f"INFO: Checking for duplicates in '{DATABASE_FILE}'...")

    cve_data: list = []
    # Step 1: Read the existing database file.
    try:
        with open(DATABASE_FILE, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Database file '{DATABASE_FILE}' not found. Please ensure it exists.")
        return
    except json.JSONDecodeError as e:
        print(f"ERROR: Could not parse the database file as JSON: {e}. Please check its format.")
        return
    except Exception as e:
        print(f"ERROR: An unexpected error occurred while reading the database: {e}")
        return

    original_count: int = len(cve_data)
    if original_count == 0:
        print("INFO: The database is empty. No action needed.")
        return

    # Step 2: Identify and remove duplicates.
    # Using a dictionary to store unique CVEs, where keys are CVE IDs.
    # This approach automatically keeps the first encountered entry for each ID.
    unique_cves: dict = {}
    for cve in cve_data:
        cve_id: str = cve.get('id')
        # Only add if 'id' exists and is not already in our unique set.
        if cve_id and cve_id not in unique_cves:
            unique_cves[cve_id] = cve
    
    # Convert the dictionary values (unique CVE objects) back to a list.
    cleaned_data: list = list(unique_cves.values())
    cleaned_count: int = len(cleaned_data)

    # Step 3: Write back the cleaned data if any duplicates were found.
    duplicates_found: int = original_count - cleaned_count
    if duplicates_found > 0:
        print(f"INFO: Found and removed {duplicates_found} duplicate(s).")
        
        try:
            with open(DATABASE_FILE, 'w', encoding='utf-8') as f:
                f.write('[\n') # Start of JSON array
                for i, entry in enumerate(cleaned_data):
                    # Dump each JSON object on a single line, ensuring compact output.
                    json.dump(entry, f, separators=(',', ':'), ensure_ascii=False)
                    if i < len(cleaned_data) - 1:
                        f.write(',\n') # Add comma and newline for all but the last entry
                    else:
                        f.write('\n') # Add newline for the last entry
                f.write(']\n') # End of JSON array
                
            print(f"SUCCESS: The database has been cleaned. Total unique CVEs: {cleaned_count}.")
        except Exception as e:
            print(f"ERROR: Failed to write cleaned data to '{DATABASE_FILE}': {e}")
    else:
        print("INFO: No duplicates found. The database is already clean.")

if __name__ == "__main__":
    # Execute the duplicate fixing function when the script is run directly.
    fix_duplicates_in_cve_db()
