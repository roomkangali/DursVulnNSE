
# DursVulnNSE Architecture Diagram

Here is a workflow diagram that visualizes how all components in the DursVulnNSE system work together.

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
                                | 
                                V  
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







