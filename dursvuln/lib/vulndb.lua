---
-- Nmap Scripting Engine (NSE) Library: Vulnerability Database (vulndb.lua)
--
-- This library provides functions to load and access a local vulnerability database,
-- typically stored in a JSON format. It's designed to be used by other NSE scripts
-- to perform vulnerability lookups based on product and version information.
--
-- @author DursVuln
-- @version 0.1.1
-- @copyright 2025
-- @license MIT
--
-- Dependencies:
--   - io: Standard Lua I/O library for file operations.
--   - dkjson: JSON parsing library for Lua.
--   - stdnse: Nmap's standard NSE library for logging and script arguments.
---

local io = require "io"
local json = require "dkjson"
local stdnse = require "stdnse"

local M = {}

-- Global hash table to store the vulnerability database, indexed by product name
-- for efficient lookups. This table is populated once the database is loaded.
local VULN_DB_BY_PRODUCT
-- Global hash table to store product aliases, mapping various product names to their standard names.
local PRODUCT_ALIASES
-- Table to store all product configurations, including detection rules.
local PRODUCT_CONFIGS

---
-- Normalizes a product key for consistent lookup.
-- Converts the string to lowercase and replaces spaces/underscores with hyphens.
-- @param s string The input string to be normalized.
-- @return string The normalized string.
---
local function normalize_key(s)
  if type(s) ~= "string" then return "" end
  return s:lower():gsub("[ _]", "-")
end

---
-- Builds the product alias dictionary and configuration table from `product.json`.
-- This function reads the `product.json` file, which contains standard product names,
-- their aliases, and other configuration details. It populates `PRODUCT_ALIASES`
-- for quick lookup of standard names and `PRODUCT_CONFIGS` for full product details.
-- (THIS FUNCTION HAS BEEN IMPROVED to use consistent key normalization).
--
-- @return boolean true if aliases and configurations were loaded successfully, false otherwise.
---
function M.load_product_aliases_and_configs()
  if PRODUCT_ALIASES and PRODUCT_CONFIGS then return true end

  local config_path = "database/product.json"
  local file, err = io.open(config_path, "r")
  if not file then
    stdnse.log_error("Could not open product config file: %s (%s)", config_path, err or "unknown error")
    PRODUCT_ALIASES = {}; PRODUCT_CONFIGS = {}
    return false
  end
  local content = file:read("*all")
  file:close()

  local status, config_data = pcall(json.decode, content)
  if not status then
    stdnse.log_error("Failed to parse JSON product config: %s", config_data)
    PRODUCT_ALIASES = {}; PRODUCT_CONFIGS = {}
    return false
  end

  PRODUCT_ALIASES = {}
  PRODUCT_CONFIGS = {}
  
  if config_data and type(config_data) == "table" then
    for _, product_entry in ipairs(config_data) do
      local std_name = product_entry.standard_name
      if std_name then
          local normalized_std_name = normalize_key(std_name)
          
          PRODUCT_CONFIGS[normalized_std_name] = product_entry
          PRODUCT_ALIASES[normalized_std_name] = normalized_std_name
          
          if product_entry.aliases and type(product_entry.aliases) == "table" then
              for _, alias in ipairs(product_entry.aliases) do
                  PRODUCT_ALIASES[normalize_key(alias)] = normalized_std_name
              end
          end
      end
    end
  end
  
  return true
end

---
-- Retrieves the standardized product name (alias) for a given product name.
-- This function uses the loaded `PRODUCT_ALIASES` to find the standard name.
-- If no alias is found, the normalized original product name is returned.
--
-- @param product_name string The product name to look up.
-- @return string The standardized product name or the normalized original.
---
function M.get_product_alias(product_name)
  if not PRODUCT_ALIASES then M.load_product_aliases_and_configs() end
    local normalized_input = normalize_key(product_name)
    return PRODUCT_ALIASES[normalized_input] or normalized_input
end

---
-- Returns the entire configuration object for a given product.
-- This function uses the loaded `PRODUCT_CONFIGS` to retrieve all details
-- associated with a standardized product name.
--
-- @param standard_name string The standardized name of the product.
-- @return table|nil The product's configuration table, or nil if not found.
---
function M.get_product_config(standard_name)
    if not PRODUCT_CONFIGS then M.load_product_aliases_and_configs() end
    if type(standard_name) ~= "string" then return nil end
    return PRODUCT_CONFIGS[normalize_key(standard_name)]
end

---
-- Loads the main CVE database from a specified JSON file.
-- The database is expected to be a JSON array of CVE entries.
-- Each entry must have 'id' and 'product' keys.
-- The loaded data is organized into a hash table (`VULN_DB_BY_PRODUCT`)
-- where keys are normalized product names and values are tables of CVE entries
-- for that product.
--
-- @param db_path_arg string|nil Optional path to the database file. If nil,
--                                defaults to "database/cve-main.json".
-- @return boolean true if the database was loaded successfully, false otherwise.
---
function M.load_vuln_database(db_path_arg)
  if VULN_DB_BY_PRODUCT then return true end
  if not M.load_product_aliases_and_configs() then return false end
  
  local db_path = db_path_arg or "database/cve-main.json"
  local file, err = io.open(db_path, "r")
  if not file then
    stdnse.log_error("Could not open database file: %s (%s)", db_path, err or "unknown error")
    return false
  end
  local content = file:read("*all")
  file:close()
  
  local status, db_or_err = pcall(json.decode, content)
  if not status then
    stdnse.log_error("Failed to parse JSON database: %s", db_or_err)
    return false
  end
  if type(db_or_err) ~= "table" then
    stdnse.log_error("JSON decoded content is not a table. Type: %s", type(db_or_err))
    return false
  end
  
  VULN_DB_BY_PRODUCT = {}
  for _, entry in ipairs(db_or_err) do
    if entry.id and entry.product then
      local product_key = normalize_key(entry.product)
      if not VULN_DB_BY_PRODUCT[product_key] then
        VULN_DB_BY_PRODUCT[product_key] = {}
      end
      table.insert(VULN_DB_BY_PRODUCT[product_key], entry)
    end
  end
  return true
end

---
-- Returns the loaded vulnerability database organized by product.
-- This function should be called after `M.load_vuln_database()` has
-- successfully loaded the data.
--
-- @return table A hash table where keys are normalized product names and
--               values are tables containing CVE entries for that product.
--               Returns nil if the database has not been loaded.
---
function M.get_vuln_db_by_product()
    return VULN_DB_BY_PRODUCT
end

return M
