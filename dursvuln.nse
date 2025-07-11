---
-- Nmap Scripting Engine (NSE) Script: dursvuln.nse 
--
-- This script performs vulnerability detection by leveraging a local CVE database
-- and product detection rules. It identifies potential vulnerabilities based on
-- (UPGRADED) This function now supports nested arrays for OR logic.
-- e.g., { {">=1.0", "<1.5"}, {">=2.0", "<2.5"} } means (>=1.0 AND <1.5) OR (>=2.0 AND <2.5)
--
-- @author DursVuln
-- @version 0.1.2
-- @copyright 2025
-- @license MIT
--
-- Dependencies:
--   - nmap: Nmap's core library for host and port information.
--   - stdnse: Nmap's standard NSE library for logging, script arguments, etc.
--   - string: Standard Lua string manipulation library.
--   - http: Nmap's HTTP library for web interactions.
--   - shortport: Nmap's library for common port rules.
--   - vulndb: Custom library for loading and accessing the vulnerability database.
---

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local http = require "http"
local shortport = require "shortport"
local mysql = require "mysql"
local ftp = require "ftp"
local redis_ok, redis = pcall(require, "redis")

-- Add the custom library path to Lua's package.path
package.path = "./dursvuln/lib/?.lua;" .. package.path
local vulndb = require "vulndb"

---
-- Defines the rule for when this script should run.
-- The script will run if the port is open and Nmap has identified
-- either a product version or a service name for that port.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @return boolean: True if the script should run, false otherwise.
---
portrule = function(host, port)
  return port.state == "open" and (port.version and port.version.product or port.service)
end

---
-- Checks for a major version mismatch between a target version and a CVE summary.
-- This helps in filtering out irrelevant CVEs where the major version clearly doesn't match.
--
-- @param target_version string: The version string of the target application.
-- @param cve_summary string: The summary text of the CVE, which may contain version info.
-- @return boolean: True if a major version mismatch is detected, false otherwise.
---
function major_version_mismatch(target_version, cve_summary)
  if not target_version or not cve_summary then return false end
  local target_major = target_version:match("^(%d+)")
  if not target_major then return false end
  local cve_major = cve_summary:match("[vV]ersion (%d+)") or cve_summary:match(" v(%d+)%.") or cve_summary:match(" (%d+)%.[x%d]+ series") or cve_summary:match(" Apache (%d+)%.")
  if cve_major and cve_major ~= target_major then return true end
  return false
end

---
-- Filters out CVEs based on negative keywords in the summary.
--
-- @param cve_summary string: The summary text of the CVE.
-- @param product_name string: The name of the product.
-- @return boolean: True if a negative keyword is found, false otherwise.
---
local function negative_keywords_filter(cve_summary, product_name)
    local lower_summary = string.lower(cve_summary)
    local lower_product = string.lower(product_name)

    -- Define negative keywords for different products
    local negative_keywords = {
        linux = {"ios", "macos", "windows", "android", "solaris"},
        windows = {"linux", "ios", "macos", "android", "solaris"},
        openssh = {"ios", "android"},
    }

    local keywords_to_check = negative_keywords[lower_product]
    if keywords_to_check then
        for _, keyword in ipairs(keywords_to_check) do
            if string.find(lower_summary, keyword) then
                return true
            end
        end
    end

    return false
end

---
-- Filters out CVEs based on architecture keywords in the summary.
--
-- @param cve_summary string: The summary text of the CVE.
-- @param port table: Nmap port object.
-- @return boolean: True if an architecture mismatch is found, false otherwise.
---
local function architecture_filter(cve_summary, port)
    local lower_summary = string.lower(cve_summary)
    local arch_keywords = {"x86", "x64", "arm", "powerpc", "64-bit", "32-bit"}
    local target_arch = port.version and port.version.ostype and string.lower(port.version.ostype) or ""

    for _, keyword in ipairs(arch_keywords) do
        if string.find(lower_summary, keyword) and not string.find(target_arch, keyword) then
            return true
        end
    end

    return false
end

---
-- Helper function to check a single set of AND conditions.
-- This contains the logic of the old `check_all_conditions` function.
-- @param version string: The version string to check.
-- @param conditions table: A flat table of version condition strings.
-- @return boolean: True if the version satisfies all conditions, false otherwise.
---
local function check_and_conditions(version, conditions)
  for _, condition in ipairs(conditions) do
    if not compare_versions(version, condition) then
      return false
    end
  end
  return true
end

---
-- Checks if a given version satisfies all specified conditions.
-- (UPGRADED) This function now supports nested arrays for OR logic.
-- e.g., { {">=1.0", "<1.5"}, {">=2.0", "<2.5"} } means (>=1.0 AND <1.5) OR (>=2.0 AND <2.5)
-- @param version string: The version string to check.
-- @param conditions table: A table of version condition strings.
-- @return boolean: True if the version satisfies the conditions, false otherwise.
---
function check_all_conditions(version, conditions)
  -- Check if the first element is a table. If so, it's a nested array (OR logic).
  if type(conditions[1]) == "table" then
    for _, inner_conditions in ipairs(conditions) do
      -- If the version matches ANY of the inner groups, it's a success.
      if check_and_conditions(version, inner_conditions) then
        return true
      end
    end
    -- If we looped through all inner groups and found no match.
    return false
  else
    -- It's a flat array, use the old AND logic for backward compatibility.
    return check_and_conditions(version, conditions)
  end
end


---
-- Compares two version strings based on a specified operator.
-- Supports operators like "==", "<", "<=", ">", ">=", "!=".
-- Handles numeric and alphanumeric parts of version strings.
--
-- @param v1 string: The first version string.
-- @param v2 string: The second version string, potentially including an operator (e.g., "<=1.2.3").
-- @return boolean: True if the comparison is true, false otherwise.
---
function compare_versions(v1, v2)
  -- If the target version string is empty, no comparison can be valid.
  if not v1 or v1 == "" then return false end
  if not v2 then return false end
  if v2 == "*" then return true end -- Wildcard match
  
  local operator, version_to_compare = string.match(v2, "^([<>=!]+)%s*(.+)")
  if not operator then
    operator = "=="; version_to_compare = v2 -- Default to equality if no operator
  end

  local function to_parts(s)
    if type(s) ~= "string" then s = tostring(s) end
    local parts = {};
    local sanitized_s = s:gsub("[^%w%.%-]", ""); -- Remove non-alphanumeric, non-dot, non-hyphen chars
    for part in string.gmatch(sanitized_s, "[^%.]+") do
      table.insert(parts, tonumber(part) or part) -- Convert to number if possible
    end
    return parts
  end

  local v1_parts = to_parts(v1);
  local v2_parts = to_parts(version_to_compare);
  
  local max_len = math.max(#v1_parts, #v2_parts);

  for i = 1, max_len do
    local p1 = v1_parts[i] or 0;
    local p2 = v2_parts[i] or 0;

    -- If types are different, treat as strings for comparison to avoid errors
    if type(p1) ~= type(p2) then
      p1 = tostring(p1)
      p2 = tostring(p2)
    end

    if p1 < p2 then
      return (operator == "<" or operator == "<=" or operator == "!=")
    elseif p1 > p2 then
      return (operator == ">" or operator == ">=" or operator == "!=")
    end
  end
  -- If all parts are equal, check for equality or inclusive operators
  return (operator == "==" or operator == "<=" or operator == ">=")
end

---
-- Handles detection rules based on HTTP headers.
-- It performs an HTTP GET request to the root path and attempts to extract
-- version information from a specified header using a regex.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @param rule table: A rule table containing 'name' (header name) and 'regex'.
-- @return string|nil: The extracted version string if a match is found, otherwise nil.
---
local function handle_http_header(host, port, rule)
    local response = http.get(host, port, "/")
    if not (response and response.header) then return nil end
    local header_value = response.header[string.lower(rule.name)]
    if header_value then
        return string.match(header_value, rule.regex)
    end
    return nil
end

---
-- Handles detection rules based on HTML body content.
-- It performs an HTTP GET request to a specified path (or root) and attempts
-- to extract version information from the HTML body using a regex.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @param rule table: A rule table containing 'path' (optional) and 'regex'.
-- @return string|nil: The extracted version string if a match is found, otherwise nil.
---
local function handle_html_body(host, port, rule)
    local path = rule.path or "/"
    local response = http.get(host, port, path)
    if not (response and response.body) then return nil end
    return string.match(response.body, rule.regex)
end

---
-- Handles detection rules based on service banners.
-- It uses the banner information already captured by Nmap.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @param rule table: A rule table containing 'regex'.
-- @return string|nil: The extracted version string if a match is found, otherwise nil.
---
local function handle_banner_grab(host, port, rule)
    if not (port.version and port.version.banner) then return nil end
    return string.match(port.version.banner, rule.regex)
end

---
-- Handles detection rules based on SQL queries (currently for MySQL).
-- It connects to the database, runs a query, and extracts version info.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @param rule table: A rule table containing 'query' and 'regex'.
-- @return string|nil: The extracted version string if a match is found, otherwise nil.
---
local function handle_sql_query(host, port, rule)
    -- Manual connection logic for older Nmap mysql library
    local sock = nmap.new_socket()
    local status, err = sock:connect(host, port)
    if not status then
        stdnse.debug1("Socket connection failed: %s", err)
        return nil
    end

    local greet_status, greeting = mysql.receiveGreeting(sock)
    if not greet_status then
        sock:close()
        stdnse.debug1("Failed to receive MySQL greeting: %s", tostring(greeting))
        return nil
    end

    -- Attempt login with nil credentials
    local login_status, _ = mysql.loginRequest(sock, greeting, nil, nil, nil)
    if not login_status then
        sock:close()
        stdnse.debug1("Login request failed")
        return nil
    end

    -- Run query
    local query_status, query_result = mysql.sqlQuery(sock, rule.query, greeting.capabilities)
    sock:close()

    if not query_status then
        stdnse.debug1("MySQL query failed: %s", tostring(query_result))
        return nil
    end

    -- Process result
    if type(query_result) == "table" and query_result[1] and query_result[1][1] then
        return string.match(tostring(query_result[1][1]), rule.regex)
    end

    return nil
end

---
-- Handles detection rules based on Redis commands.
-- It connects to the Redis server, runs a command (e.g., INFO server),
-- and extracts version information from the response using a regex.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @param rule table: A rule table containing 'command' and 'regex'.
-- @return string|nil: The extracted version string if a match is found, otherwise nil.
---
local function handle_redis_command(host, port, rule)
    if not redis_ok then
        stdnse.debug1("Redis library not available, skipping redis_command rule.")
        return nil
    end
    local status, client = redis.connect(host, port)
    if not status then
        stdnse.debug1("Redis connection failed: %s", client)
        return nil
    end

    local query_status, query_result = client:query(rule.command)
    redis.close(client)

    if not query_status then
        stdnse.debug1("Redis command failed: %s", query_result)
        return nil
    end

    if type(query_result) == "string" then
        return string.match(query_result, rule.regex)
    end

    return nil
end

---
-- Handles detection rules based on HTTP file content.
-- It performs an HTTP GET request to a specified path and attempts
-- to extract version information from the file's content using a regex.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @param rule table: A rule table containing 'path' and 'regex'.
-- @return string|nil: The extracted version string if a match is found, otherwise nil.
---
local function handle_http_file_content(host, port, rule)
    local response = http.get(host, port, rule.path)
    if not (response and response.body) then return nil end
    return string.match(response.body, rule.regex)
end

---
-- Handles detection rules based on FTP banners.
-- It connects to the FTP server and uses the initial banner response.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @param rule table: A rule table containing 'regex'.
-- @return string|nil: The extracted version string if a match is found, otherwise nil.
---
local function handle_ftp_banner(host, port, rule)
    local status, banner = ftp.connect(host, port)
    if not status then
        stdnse.debug1("FTP connection failed: %s", banner)
        return nil
    end
    ftp.close(banner)
    if banner then
        return string.match(banner, rule.regex)
    end
    return nil
end

---
-- Dispatches to the appropriate handler to get the application version
-- based on the detection rules defined in the product configuration.
-- This function iterates through the detection rules and calls the relevant
-- handler (e.g., `handle_http_header`, `handle_html_body`) to find the version.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @param product_config table: The configuration table for the product,
--                              containing `detection_rules`.
-- @return string|string|nil: The detected application version and its standard name,
--                             or nil, nil if no version is found.
---
local function get_application_version(host, port, product_config)
    if not product_config or not product_config.detection_rules then
        return nil, nil
    end

    for _, rule in ipairs(product_config.detection_rules) do
        local app_version
        
        if rule.type == "http_header" and rule.name and rule.regex then
            app_version = handle_http_header(host, port, rule)
        elseif rule.type == "html_body" and rule.regex then
            app_version = handle_html_body(host, port, rule)
        elseif rule.type == "banner_grab" and rule.regex then
            app_version = handle_banner_grab(host, port, rule)
        elseif rule.type == "sql_query" and rule.query and rule.regex then
            app_version = handle_sql_query(host, port, rule)
        elseif rule.type == "ftp_banner" and rule.regex then
            app_version = handle_ftp_banner(host, port, rule)
        elseif rule.type == "redis_command" and rule.command and rule.regex then
            app_version = handle_redis_command(host, port, rule)
        elseif rule.type == "http_file_content" and rule.path and rule.regex then
            app_version = handle_http_file_content(host, port, rule)
        end

        if app_version then
            return app_version, product_config.standard_name
        end
    end

    return nil, nil
end

---
-- The main action function for the Nmap script.
-- This function is executed for each host/port pair that matches the `portrule`.
-- It loads the vulnerability database, identifies the product and its version,
-- then checks for known vulnerabilities based on the loaded CVE data.
-- It filters and formats the output based on severity and verbosity settings.
--
-- @param host table: Nmap host object.
-- @param port table: Nmap port object.
-- @return string|nil: A formatted string listing found vulnerabilities, or nil if none.
---
action = function(host, port)
  -- Get script arguments for filtering and display.
  local db_path_arg = stdnse.get_script_args("db_path")

  -- Load the vulnerability database; return error message if failed.
  if not vulndb.load_vuln_database(db_path_arg) then return "Vulnerability database could not be loaded." end

  -- Determine product display name and full version from Nmap's output.
  local product_display_name = (port.version and port.version.product) or port.service or ""
  local version_full = (port.version and port.version.version) or ""
  local primary_key

  -- Try to find a primary key (standardized product name) using aliases.
  local keys_to_try = {}
  if port.version and port.version.product then table.insert(keys_to_try, port.version.product) end
  if port.service then table.insert(keys_to_try, port.service) end
  for _, key in ipairs(keys_to_try) do
      local aliased_key = vulndb.get_product_alias(key)
      if aliased_key and aliased_key ~= "" then primary_key = aliased_key; break end
  end

  -- If no primary key is found, exit.
  if not primary_key then return nil end

  -- Get product configuration to apply custom detection rules.
  local product_config = vulndb.get_product_config(primary_key)
  
  -- If a product configuration has specific detection rules, they MUST pass.
  if product_config and product_config.detection_rules then
    
    -- Attempt to get a more accurate version using the defined rules.
    local app_version, app_name = get_application_version(host, port, product_config)

    -- If no version was found via the rules, this is not the correct product.
    -- This prevents a generic service (like Jetty) from being misidentified as
    -- a specific application (like Jenkins).
    if not app_version then
      stdnse.debug1("Product '%s' has detection rules, but none succeeded. Aborting.", primary_key)
      return nil
    end

    -- If detection was successful, we MUST overwrite the initial banner info
    -- with the more accurate data we just found.
    stdnse.debug1("Deep inspection successful. Overwriting banner info.")
    version_full = app_version
    product_display_name = app_name
    primary_key = string.lower(app_name)
  end

  -- Extract a simplified version string for comparison.
  local version = string.match(version_full, "^[%d%.a-zA-Z%-LTS]+") or version_full

  -- Get all CVEs for the identified product from the loaded database.
  local all_cves_for_product = vulndb.get_vuln_db_by_product()[primary_key]
  if not all_cves_for_product then return nil end

  local found_vulnerabilities = {}
  
  -- Get script arguments for filtering and display.
  local min_severity = stdnse.get_script_args("min_severity") or "UNKNOWN"
  local verbose = stdnse.get_script_args("verbose") == "true"
  local max_potential = tonumber(stdnse.get_script_args("max_potential")) or 3
  local output_mode = string.lower(stdnse.get_script_args("dursvuln.output") or "")

  -- Map severity strings to numeric levels for comparison.
  local severity_map = { ["UNKNOWN"]=0, ["LOW"]=1, ["MEDIUM"]=2, ["HIGH"]=3, ["CRITICAL"]=4 }
  local min_severity_level = severity_map[string.upper(min_severity)] or 0

  -- Iterate through CVEs and check for matches.
  for _, cve in ipairs(all_cves_for_product) do
      local match_type = cve.match_type or 'product_only'
      local entry_severity_level = severity_map[string.upper(cve.severity or "UNKNOWN")] or 0

      -- Filter by minimum severity level.
      if entry_severity_level >= min_severity_level then
          local passed_filter = false

          -- Apply matching logic based on match_type.
          if match_type == 'version_range' and cve.version_match then
              if type(cve.version_match) == "string" then
                passed_filter = compare_versions(version, cve.version_match)
              elseif type(cve.version_match) == "table" then
                passed_filter = check_all_conditions(version, cve.version_match)
              end
              if passed_filter then cve.report_confidence = "High" end
          elseif match_type == 'product_only' then
              if not major_version_mismatch(version, cve.summary) and
                 not negative_keywords_filter(cve.summary, primary_key) and
                 not architecture_filter(cve.summary, port) then
                passed_filter = true; cve.report_confidence = "Low"
              end
          elseif match_type == 'active_check' and cve.required_script then
              passed_filter = true;
              cve.report_confidence = "CRITICAL (Active Check Required)";
              cve.report_note = string.format("Vulnerability status must be confirmed by running --script=%s", cve.required_script)
          end

          -- If the CVE passes the filter, add it to found vulnerabilities.
          if passed_filter then table.insert(found_vulnerabilities, cve) end
      end
  end

  -- Format and return the output.
  if #found_vulnerabilities > 0 then
      local output_lines = {};
      table.insert(output_lines, string.format("Vulnerabilities found for %s %s", product_display_name, version))
      
      local potential_shown = 0
      local potential_hidden = 0

      -- Sort vulnerabilities by severity (highest first).
      table.sort(found_vulnerabilities, function(a, b) return (severity_map[a.severity] or 0) > (severity_map[b.severity] or 0) end)

      for _, vuln in ipairs(found_vulnerabilities) do
          local should_show = true
          -- Handle limiting "Low" confidence potential findings.
          if vuln.report_confidence == "Low" then
            -- In 'full' mode, we act as if 'verbose' is true.
            if not (verbose or output_mode == "full") and potential_shown >= max_potential then
              should_show = false
              potential_hidden = potential_hidden + 1
            else
              potential_shown = potential_shown + 1
            end
          end

          if should_show then
              if output_mode == "concise" then
                  local title
                  if vuln.report_confidence == "CRITICAL (Active Check Required)" then
                      title = string.format("  %s (Active Check Required): %s (%s Confidence)", string.upper(vuln.severity or "UNKNOWN"), vuln.id, string.upper(vuln.confidence or "N/A"))
                      table.insert(output_lines, title)
                      if vuln.report_note then
                          table.insert(output_lines, string.format("    Note: %s", vuln.report_note))
                      end
                  elseif vuln.report_confidence == "Low" then
                      title = string.format("  POTENTIAL (Low Confidence): %s", vuln.id)
                      table.insert(output_lines, title)
                      table.insert(output_lines, "    Note: Manual verification required.")
                  else -- High Confidence
                      title = string.format("  ID: %s (%s Confidence)", vuln.id, vuln.report_confidence or "N/A")
                      table.insert(output_lines, title)
                  end
              else -- Default "full" or legacy output
                  local title
                  if vuln.report_confidence == "CRITICAL (Active Check Required)" then
                      title = string.format("  %s (Active Check Required): %s", string.upper(vuln.severity or "UNKNOWN"), vuln.id)
                  elseif vuln.report_confidence == "Low" then
                      title = string.format("  POTENTIAL (%s Confidence): %s", vuln.report_confidence, vuln.id)
                  else
                      title = string.format("  ID: %s (%s Confidence)", vuln.id, vuln.report_confidence or "N/A")
                  end
                  table.insert(output_lines, title)
                  table.insert(output_lines, string.format("    Severity: %s", vuln.severity))
                  table.insert(output_lines, string.format("    Summary: %s", vuln.summary))
                  
                  -- Add references if available.
                  if type(vuln.references) == "table" and #vuln.references > 0 then
                    table.insert(output_lines, string.format("    References: %s", table.concat(vuln.references, ", ")))
                  elseif type(vuln.references) == "string" then
                    table.insert(output_lines, string.format("    References: %s", vuln.references))
                  end
                  
                  -- Add notes for active checks or low confidence.
                  if vuln.report_note then
                    table.insert(output_lines, string.format("    Note: %s", vuln.report_note))
                  elseif vuln.report_confidence == "Low" then
                    table.insert(output_lines, "    Note: Manual verification required.")
                  end
              end
          end
      end

      -- Add a summary for hidden potential findings.
      if potential_hidden > 0 then
        local see_all_arg
        if output_mode == "concise" then
          see_all_arg = "dursvuln.output=full"
        else
          see_all_arg = "dursvuln.verbose=true"
        end
        table.insert(output_lines, string.format("  ...and %d other potential findings. Use --script-args=%s to see all.", potential_hidden, see_all_arg))
      end
      
      return table.concat(output_lines, "\n")
  end
  return nil
end
