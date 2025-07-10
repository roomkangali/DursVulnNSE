# ℹ️ DursVuln - Nmap Scripting Engine (NSE)

<p align="center">
  <img src="dursvuln-logo.png" width="500">
</p>

<h3 align="center">📦 Package Attributes</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Linux-Supported-brightgreen?style=for-the-badge&logo=linux" alt="Linux Supported">
  <img src="https://img.shields.io/badge/macOS-Supported-brightgreen?style=for-the-badge&logo=apple" alt="macOS Supported">
  <img src="https://img.shields.io/badge/Windows-Supported-brightgreen?style=for-the-badge&logo=windows" alt="Windows Supported">
</p>

---

<div align="center">
  <table>
    <tr>
      <td align="center" valign="top">
        <strong>DursVulnNSE: Demo Vulhub Lab</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=A6_YR7VMzWk" target="_blank">
          <img src="https://img.youtube.com/vi/A6_YR7VMzWk/hqdefault.jpg" alt="Demo 1" width="100%"/>
        </a>
      </td>
      <td align="center" valign="top">
        <strong>DursVulnNSE: Detect EternalBlue (MS17-010)</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=aGMu7YYoNpg" target="_blank">
          <img src="https://img.youtube.com/vi/aGMu7YYoNpg/hqdefault.jpg" alt="Demo 2" width="100%"/>
        </a>
      </td>
    </tr>
  </table>
</div>

---

## 📝 Table of Contents
- ℹ️ [About DursVulnNSE](#about-dursvulnnse)
- 💡 [Why DursVuln?](#why-dursvuln)
- 🏗️ [System Architecture](#system-architecture)
- ✨ [Features](#features)
- 👥 [User Group](#user-group)
- 📦 [Installation](#installation)
  - ⚪ [Update Database](#update-database)
  - ⚪ [Option 1: Running Locally (Recommended for Development)](#option-1-running-locally-recommended-for-development)
  - ⚪ [Option 2: Installation](#option-2-installation)
    - ⚪ [Automated Installation using `configure-dursvuln.sh`](#automated-installation-using-configure-dursvulnsh)
- ⌨️ [Usage](#usage)
  - ⚪ [Script Arguments](#script-arguments)
- 📊 [Understanding the Report](#understanding-the-report)
- 🗄️ [Database Management](#database-management)
  - ⚪ [Updating the Database](#updating-the-database)
  - ⚪ [Cleaning Duplicate Entries](#cleaning-duplicate-entries)
- 📄 [Database Structure](#database-structure)
  - ⚪ [Product Configuration (`product.json`)](#product-configuration-productjson)
  - ⚪ [Script Mapping (`script_mapping.json`)](#script-mapping-scriptmappingjson)
  - ⚪ [Entry Structure (`cve-main.json`)](#entry-structure-cve-mainjson)
  - ⚪ [Version Matching Logic](#version-matching-logic)
  - ⚪ [Adding Manual Entries](#adding-manual-entries)
- 🔧 [Customization & Development](#customization--development)
- 🗺️ [Future Roadmap](#future-roadmap)
- 🤝 [Contributions](#contributions)
- 🙏 [Thanks To](#thanks-to)


# ℹ️  About DursVulnNSE

DursVulnNSE is an open-source Nmap Scripting Engine (NSE) script designed to identify vulnerabilities in detected services. Inspired by [`scipag/vulscan`](https://github.com/scipag/vulscan) and [`vulnersCom/nmap-vulners`](https://github.com/vulnersCom/nmap-vulners), this project features a modular architecture and an easily updatable database to provide detailed, accurate, and readable vulnerability reports. DursVulnNSE stands out in the Nmap community due to its unique approach to vulnerability scanning. Unlike many existing solutions, DursVulnNSE offers a highly customizable and efficient local vulnerability database.


## 💡 Why DursVuln?

DursVulnNSE fills a significant gap in the Nmap ecosystem by offering flexible, and user-friendly solution for local vulnerability scanning, addressing common challenges like false positives and delayed updates often encountered with online or less customizable tools.Ideal for internal penetration testing, air-gapped environments, or when privacy is a top priority.

## 🏗️ System Architecture
DursVulnNSE uses a two-component architecture to maximize efficiency: offline data processing and scan-time execution.

**Offline Processing Component (`db_updater.py`):** This component is responsible for all resource-intensive tasks. It reads configuration files (`product.json` & `script_mapping.json`), fetches raw data from the NVD API, then performs an enrichment process to classify and format each CVE. The final result is a structured and optimized `cve-main.json` file.

**Scan-Time Execution Component (`dursvuln.nse` & `vulndb.lua`):** This component is designed to be lightweight and fast. When Nmap runs, it only loads the pre-processed `cve-main.json` data into memory. Its task is to perform efficient matching against targets, apply filtering logic, and present the final report without needing heavy data processing.

**Layered Application Detection**: Capable of "looking deeper" than just web server versions, by detecting actual application versions from HTTP headers or HTML content (e.g., Jenkins on Jetty).


```
+-------------------------------------------------------------------------+
| PHASE 1: DATA PREPARATION (OFFLINE) -                                   |
|                                                                         |
|  [+] Configuration Input                                                |
|   |                                                                     |
|   |--- [ product.json ]                                                 |
|   |    (Command Center: List of products, aliases, & detection rules)   |
|   |                                                                     |
|   '--- [ script_mapping.json ]                                          |
|        (Active Script Mapping File)                                     |
|                                                                         |
|       |                                                                 |
|       V                                                                 |
|                                                                         |
|  [>] Core Process: Data Enrichment Engine                               |
|   |                                                                     |
|   |    +---------------------+                                          |
|   |    |   db_updater.py     | <--- (Fetching data) ---- [ NVD API ]    |
|   |    +---------------------+                                          |
|   |           |                                                         |
|   |           V (Reads configuration, downloads, & enriches data)       |
|   |                                                                     |
|   '-> [>] Output: Ready-to-Use Database                                 |
|           |                                                             |
|           V                                                             |
|    +------------------+                                                 |
|    |  cve-main.json   | (The intelligent and optimized database)        |
|    +------------------+                                                 |
|                                                                         |
+-------------------------------------------------------------------------+
```
```
+-------------------------------------------------------------------------+
| PHASE 2: EXECUTION (SCAN-TIME) - Executed by Nmap                       |
|                                                                         |
|  [+] Trigger: Nmap Command                                              |
|   |                                                                     |
|   '--- > nmap -sV --script dursvuln <target>                            |
|                                                                         |
|           |                                                             |
|           V                                                             |
|                                                                         |
|  [>] Core Process: Intelligent Scanning Engine                          |
|   |                                                                     |
|   |    +---------------------------+                                    |
|   |    |    dursvuln.nse           |                                    |
|   |    |  (NSE Script/Executor)    |                                    |
|   |    +---------------------------+                                    |
|   |           ^                                                         |
|   |           | (Requests data & configuration)                         |
|   |           |                                                         |
|   |    +----------------------------+                                   |
|   |    |     vulndb.lua             | <-- (cve-main.json)               |
|   |    | (Database Library/Manager) | <-- (product.json)                |
|   |    +----------------------------+                                   |
|   |           |                                                         |
|   |           V (Applies filters, compares versions, & formats)         |
|   |                                                                     |
|   '-> [>] Output: Final Report                                          |
|           |                                                             |
|           V                                                             |
|    +------------------+                                                 |
|    |    Nmap Report   | (Displays High/Low Confidence findings, etc.)   |
|    +------------------+                                                 |
|                                                                         |
+-------------------------------------------------------------------------+
```

## ✨ Features
-   **Dynamic Service Detection**: Automatically runs on any open port where Nmap has successfully detected a service and its version.
-   **Output Control (`dursvuln.output`)**: Controls the verbosity and format of the scan report.
    -   `dursvuln.output=concise` (Default): Provides a clean, summarized report focusing on critical and high-confidence findings, with low-confidence findings limited and noted for manual verification.
    -   `full`: Displays all available technical details for every vulnerability, similar to using `dursvuln.verbose=true`.
-   **Severity Filtering**: Allows users to filter scan results based on a minimum severity level (`min_severity`).
-   **Database Updater**: Includes Python scripts (`db_updater.py`, `fix_duplicate.py`) for fetching the latest CVE data from NVD and maintaining database integrity.
-   **Layered Application Detection**: Capable of "looking deeper" than just web server versions, by detecting actual application versions from HTTP headers or HTML content (e.g., Jenkins on Jetty).

# 👥 User Group

DursVulnNSE solves real problems faced by various user groups every day.

### 🛡️ For Red/Blue Team

-   **Internal/Air-Gapped Networks**
-   **Project-Specific Rule Customization**
-   **Adding Non-Public Vulnerabilities**

### 🐞 For Bug Hunters

-   **Efficiency**
-   **Personal Finding Management**

### 📚 For Training Cyber Security

-   **Learning Environment**
-   **Educational Tool**

---

## 📦 Installation

Ensure that Nmap version `7.94SVN` or later is installed for stability. The Nmap distribution can be downloaded from [`nmap.org/dist`](https://nmap.org/dist/)

Clone Repo:

```bash
git clone https://github.com/roomkangali/DursVulnNSE
cd DursVulnNSE
```

### Update Database

Execution of `db_updater.py` is required to select CVEs for inclusion in the database. An existing CVE database can be utilized to populate `cve-main.json`, and `product.json` must be updated to conform to the format required by the DursVulnNSE scanner. Refer to the Database Management section for detailed instructions.

### Option 1: Running Locally (Recommended for Development)

This is the easiest way to get started. Nmap can be run from the project's root directory by providing the path to the script file.

```bash
# Example scan on a single port
sudo nmap -sV -Pn 21 --script ./dursvuln.nse <target_ip>

# Example scan on ports
sudo nmap -sV -Pn --script ./dursvuln.nse <target_ip>
```

### Option 2:  Installation

#### Automated Installation using `configure-dursvuln.sh`

This script automates the entire global installation process, including copying files, adjusting paths, and updating the Nmap script database.
The correct Nmap data directory (e.g., `/usr/local/share/nmap` or `/usr/share/nmap`) must be specified.

**Steps:**

1.  **Make the script executable:**
    ```bash
    chmod +x configure-dursvuln.sh
    ```
2.  **Run the script:**
    ```bash
    sudo ./configure-dursvuln.sh
    ```
    The script will prompt for the Nmap data directory.

---

## ⌨️ Usage

Once installed, run the script by calling its name.

**Basic Scan:**
```bash
sudo nmap -sV --script=dursvuln <target_ip>
```

**Scan Check Ports:**
```bash
sudo nmap -sV -Pn --script=dursvuln <target_ip>
```

### Script Arguments
```
-   `db_path`: Specifies a custom path to the JSON vulnerability database file.
    ```bash
    sudo nmap -sV -Pn --script=dursvuln --script-args="db_path=/path/to/cve-main.json" <target_ip>
    ```
-   `min_severity`: Filters the output to only show vulnerabilities with a specified severity level or higher. Options: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
    ```bash
    sudo nmap -sV -Pn --script=dursvuln --script-args="min_severity=HIGH" <target_ip>
    ```
-   `verbose`: Displays all potential findings, including those with "Low Confidence".
    ```bash
    sudo nmap -sV -Pn --script=dursvuln --script-args="dursvuln.verbose=true" <target_ip>
    ```
-   `dursvuln.output`: Controls the verbosity and format of the scan report.
    -   `concise` (Default): Provides a clean, summarized report focusing on critical and high-confidence findings, with low-confidence findings limited and noted for manual verification.
        ```bash
        sudo nmap -sV -Pn --script=dursvuln --script-args="dursvuln.output=concise" <target_ip>
        ```
    -   `full`: Displays all available technical details for every vulnerability, similar to using `verbose=true`.
        ```bash
        sudo nmap -sV -Pn --script=dursvuln --script-args="dursvuln.output=full" <target_ip>
        ```
    **Note:** Existing arguments (`min_severity`, `verbose`, `max_potential`) remain functional for backward compatibility. The summary message for hidden potential findings will now intelligently suggest the correct argument (`dursvuln.output=full` or `dursvuln.verbose=true`) based on the current output mode.
```
<div align="center">
  <table>
    <tr>
      <td align="center" valign="top">
        <strong>DursVulnNSE: Output (Concise vs. Full) while Hunting Log4j</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=of26aGXF1f0" target="_blank">
          <img src="https://img.youtube.com/vi/of26aGXF1f0/hqdefault.jpg" alt="Demo 2" width="100%"/>
        </a>
      </td>
    </tr>
  </table>
</div>

---

## 📊 Understanding the Report
DursVulnNSE classifies each finding based on its confidence level:

-   **ID: ... (High Confidence)**: Strong evidence. The target version matches a known vulnerable version range. High Priority.
-   **... (Active Check Required): ...**: Critical potential risk. The scanner provides another Nmap command that should be run for verification. Urgent Priority for Verification.
-   **POTENTIAL (Low Confidence): ...**: Weak evidence. The product name matches, but there is no clear version data. Requires manual verification. Low Priority.

---

## 🗄️ Database Management

### Updating the Database

Update the vulnerability database with the latest data from the NVD (National Vulnerability Database) using the `db_updater.py` script. This script fetches new CVEs for predefined products and integrates them into `cve-main.json` file, preventing duplicates.

The `db_updater.py` script supports two primary methods for updating the database:

1.  **Automated Product Updates**: The script will download the latest CVEs for a predefined list of products (e.g., Apache, OpenSSH, Nginx) based on `product.json`.
2.  **Single CVE Addition**: Individual CVEs can be specified for addition to the database, which is useful for specific vulnerabilities not covered by mass product updates or for testing.

```bash
# Install required Python libraries (if not already installed)
pip install requests

# Run the updater to fetch and update the main database
python3 tools/db_updater.py
```

### Cleaning Duplicate Entries

If entries are manually added to `cve-main.json` or if other processes introduce redundant CVEs, the `fix_duplicate.py` script can be used to clean the database. This script ensures that each CVE ID appears only once.

```bash
# Run the script to remove duplicate entries
python3 tools/fix_duplicate.py
```

<div align="center">
  <table>
    <tr>
      <td align="center" valign="top">
        <strong>DursVulnNSE: How to Add New CVEs and Fix Duplicate Entries</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=thipQpQPn-A" target="_blank">
          <img src="https://img.youtube.com/vi/thipQpQPn-A/hqdefault.jpg" alt="Demo 2" width="100%"/>
        </a>
      </td>
    </tr>
  </table>
</div>

---

## Database Structure

The `cve-main.json` vulnerability database is the core of this script. It is a JSON array of objects, where each object represents a single vulnerability entry. For efficiency with large datasets, each JSON object is stored on a single line within the array.

**Performance Note:** This database has been tested with up to 250,000 CVE entries, and scanning operations have performed normally without any crashes.

### Product Configuration (`product.json`)

The `product.json` file serves as the "Command Center" for the entire DursVulnNSE system. It is the single source of truth for all product-related configurations.

**Example `product.json` Entry:**
```json
  {
    "standard_name": "mysql",
    "search_term": "cpe:2.3:a:mysql:mysql",
    "aliases": ["mysql", "mariadb"]
  }
```
```
-   `standard_name` (Required): The canonical or standard name for the product (e.g., "apache http server", "mysql").
-   `search_term` (Required): The search term used by `db_updater.py` to fetch data from the NVD API (preferably a CPE string).
-   `aliases` (Required, can be empty): A list of other names Nmap might report for the same product (e.g., "samba smbd" for "samba").
-   `detection_rules` (Optional): A list of instructions for `dursvuln.nse` on how to perform deep inspection to get the actual application version (e.g., from HTTP headers or HTML content). Each rule has:
    -   `type` (e.g., "http_header", "html_body")
    -   `name` (optional, e.g., header name)
    -   `regex` (Lua pattern to extract version)
    -   `path` or `query` (optional, for specific resource access)
```
**Example `detection_rules`:**

-   **Detecting Jenkins version from HTTP header:**
    ```json
    "detection_rules": [
      {
        "type": "http_header",
        "name": "x-jenkins",
        "regex": "([%d%.%-LTS]+)"
      }
    ]
    ```

### Script Mapping (`script_mapping.json`)

The `script_mapping.json` file is an intelligent dictionary that links passive vulnerabilities to active testing. It defines which Nmap script should be recommended for specific critical CVEs that require verification.

**Example `script_mapping.json`:**
```json
{
  "CVE-2017-0144": "smb-vuln-ms17-010",
  "CVE-2024-4577": "php-cgi-cve-2024-4577"
}
```
-   Key: CVE ID (e.g., "CVE-2017-0144")
-   Value: Name of the corresponding Nmap NSE script (e.g., "smb-vuln-ms17-010")

### Entry Structure (`cve-main.json`)

Each entry in `cve-main.json` should have the following keys:
```
-   `id` (String): A unique identifier for the vulnerability (e.g., "CVE-2023-12345", "APACHE-LOG4J-RCE").
-   `product` (String): The name of the vulnerable product or service. Matching is case-insensitive.
-   `summary` (String): A brief summary of the vulnerability.
-   `details` (String): A more detailed explanation of the vulnerability.
-   `references` (String or Array of Strings): Link(s) to external resources for more information (e.g., advisories, blog posts).
-   `severity` (String): The severity level of the vulnerability. Valid values are `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
-   `match_type` (String): Indicates how the CVE was matched. Added by `db_updater.py`. Values:
    -   `"version_range"`: CVE has clear version rules.
    -   `"product_only"`: CVE applies to the product generally, no clear version rules.
    -   `"active_check"`: Critical CVE requiring active testing.
-   `confidence` (String): Confidence level determined by `db_updater.py` based on `match_type`. Values: `"high"`, `"low"`.
-   `version_match` (String or Array of Strings, Optional): Rule(s) for matching service versions. Only present if `match_type` is `"version_range"`.
-   `required_script` (String, Optional): Name of the recommended Nmap script for verification. Only present if `match_type` is `"active_check"`.
```
### Version Matching Logic

The script uses a flexible version comparison function that handles various scenarios:

1.  **Exact Match**: If no operator is specified, the script looks for an exact version match.
    -   Example: `"2.4.1"` will only match version "2.4.1".

2.  **Comparison Operators**: Use operators to define version ranges.
```
    -   `>`: Greater than
    -   `>=`: Greater than or equal to
    -   `<`: Less than
    -   `<=`: Less than or equal to
    -   `==`: Exactly equal to (explicitly, though implied by no operator)
    -   `!=`: Not equal to
    -   Example: `"<9.2"` will match any version before 9.2.
```
3.  **Wildcards**: Use `*` or `x` as wildcards to match any version segment.
    -   Example: `"8.x"` will match any version starting with "8.", such as "8.1", "8.9p1", etc.

4.  **Multiple Conditions (Array)**: For more complex scenarios, provide an array of strings where each string is a condition. All conditions within the array must be met for a match to occur.
    -   Example: `[ ">=5.0", "<5.1.2" ]` will match any version greater than or equal to 5.0 AND less than 5.1.2.

### Adding Manual Entries

To add new vulnerabilities manually, edit the `database/cve-main.json` file and append new JSON objects to the array. Ensure JSON format remains valid. After manual additions, it is recommended to run `python3 tools/fix_duplicate.py` to ensure no duplicate IDs were introduced.

**Example Manual Entry:**

```json
[
  {"id":"CVE-2017-0144","product":"microsoft-ds","summary":"The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka \"Windows SMB Remote Code Execution Vulnerability.\" This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.","details":"The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka \"Windows SMB Remote Code Execution Vulnerability.\" This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.","references":["http://packetstormsecurity.com/files/154690/DOUBLEPULSAR-Payload-Execution-Neutralization.html","http://packetstormsecurity.com/files/156196/SMB-DOUBLEPULSAR-Remote-Code-Execution.html","http://www.securityfocus.com/bid/96704"],"severity":"HIGH","match_type":"active_check","confidence":"high","required_script":"smb-vuln-ms17-010"},
  {"id": "CVE-2021-4104", "product": "apache log4j", "summary": "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.", "details": "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.", "references": ["http://www.openwall.com/lists/oss-security/2022/01/18/3", "https://access.redhat.com/security/cve/CVE-2021-4104", "https://github.com/apache/logging-log4j2/pull/608#issuecomment-990494126"], "severity": "HIGH", "match_type": "version_range", "confidence": "high", "version_match": ["<11.2.8.0", "<12.0.0.4.0", "<=8.0.29"]}
]
```

---

## 🔧 Customization & Development
The power of DursVuln lies in its flexibility.

-   **Adding New Products**: A new entry can be added to `product.json`.
-   **Adding Aliases**: New alias names can be added to the `aliases` list of an existing product in `product.json`.
-   **Adding Advanced Detection Rules**: `detection_rules` objects can be added to a product in `product.json` to enable the scanner to find application versions (e.g., from HTTP headers or HTML content).
-   **Adding Active Test Mappings**: "CVE-ID": "script-name.nse" pairs can be added to `script_mapping.json` to enhance triage intelligence.

After making changes to configuration files, `python3 tools/db_updater.py` must be re-run to synchronize the main database.

---

## 🗺️ Future Roadmap
-   **Enhanced Version Detection Accuracy:**
    -   Continue to implement and refine protocol-specific versioning and identification logic within `dursvuln.nse` and `product.json` for broader and more accurate service coverage.
    -   Further improve `compare_versions` to handle complex version strings (e.g., with alphanumeric suffixes, multiple components) more robustly.
-   **Automate Active Check Script Execution:**
    -   Integrate functionality to automatically run recommended `active_check` scripts (from `script_mapping.json`) and report results directly within the   `dursvuln.nse` output.
-   **Expand Protocol Handlers:**
    -   Implement generic handlers for other common protocols (e.g., SNMP, RDP, custom application protocols) to broaden scan capabilities.
-   **Report Presentation Refinements:**
    -   **Improve Low Confidence Guidance:** Provide more specific guidance or potential next steps for `Low Confidence` findings beyond "Manual verification required." (e.g., "Consider running Nmap script X for further analysis").
    -   **Database Management Enhancements:** Further optimize `db_updater.py` for even faster and more resilient CVE data fetching from NVD, ensuring the `cve-main.json` remains up-to-date and well-curated.

---

## 🤝 Contributions
Contributions are highly welcome! Please feel free to create pull requests or open issues if you find bugs or have ideas for new features.

---

## 🙏 Thanks To

This project would not have been possible without the hard work of many people in the open-source community. Special Thanks to:

-   **The Nmap Development Team** for creating the incredible Nmap Scripting Engine (NSE), which serves as the foundation for this script.
-   **The creators behind** [`scipag/vulscan`](https://github.com/scipag/vulscan) and [`vulnersCom/nmap-vulners`](https://github.com/vulnersCom/nmap-ners) for being the primary inspiration in the development of DursVulnNSE.
-   **David Heiko Kolf** for his lightweight and efficient `dkjson.lua` library. This library is a crucial component that handles the JSON database parsing and inspired the modular approach in this script [`dkolf.de/dkjson-lua`](http://dkolf.de/dkjson-lua/).
