# Qualys CSAM Duplicate Asset Finder

A generic tool to query the Qualys Asset Management (CSAM) API and identify duplicate assets based on various criteria (IP, hostname, name, MAC, FQDN, NetBIOS).

Supports flexible filtering to narrow down asset searches.

## Features

- **Flexible Filtering**: Filter assets by any supported field (tags, OS, tracking method, IP, etc.)
- **Multiple Filter Support**: Combine multiple filters with AND logic
- **Duplicate Detection**: Identifies duplicates based on:
  - IP Address
  - DNS Hostname
  - Asset Name
  - NetBIOS Name
  - MAC Address
  - FQDN
- **Selective Checks**: Choose which duplicate criteria to check
- **Automatic Pagination**: Handles large datasets automatically
- **Multiple Export Formats**: JSON, CSV (all assets), CSV (duplicates only)
- **Multi-Platform Support**: Works with all Qualys platform regions

## Requirements

- Python 3.7+
- `requests` library

## Installation

```bash
# Install required dependency
pip install requests

# Make the script executable (Linux/Mac)
chmod +x qualys_duplicate_finder.py
```

## Configuration

### Option 1: Environment Variables

```bash
export QUALYS_USERNAME="your_username"
export QUALYS_PASSWORD="your_password"
```

### Option 2: Command Line Arguments

```bash
python qualys_duplicate_finder.py -u username -p 'password'
```

### Option 3: Configuration File

```bash
cp config.env.example config.env
# Edit config.env with your credentials
source config.env
```

## Filter Format

Filters use the format: `field:operator:value`

```bash
--filter "tagName:CONTAINS:Tenable"
--filter "os:EQUALS:Windows Server 2019"
--filter "trackingMethod:EQUALS:QAGENT"
```

### Available Filter Fields

| Category | Fields |
|----------|--------|
| **Basic** | `id`, `name`, `os`, `dnsHostName`, `address`, `fqdn`, `type` |
| **Tags** | `tagId`, `tagName` |
| **Network** | `netbiosName`, `netbiosNetworkId`, `networkGuid`, `port` |
| **Tracking** | `trackingMethod`, `qwebHostId` |
| **Dates** | `created`, `modified`, `lastVulnScan`, `lastComplianceScan`, `vulnsUpdated` |
| **Software** | `installedSoftware` |
| **AWS** | `region`, `vpcId`, `accountId`, `instanceId`, `availabilityZone`, `imageId` |
| **Azure** | `vmId`, `subscriptionId`, `location`, `resourceGroupName`, `state` |
| **GCP** | `gcpInstanceId`, `gcpProjectId`, `gcpZone` |
| **Alibaba** | `aliInstanceId`, `aliRegion`, `aliAccountId` |
| **OCI** | `ociId`, `compartmentId`, `ociRegion` |
| **IBM** | `ibmId`, `ibmLocation`, `datacenterId` |

### Available Operators

| Type | Operators |
|------|-----------|
| **Text** | `CONTAINS`, `EQUALS`, `NOT EQUALS` |
| **Integer** | `EQUALS`, `NOT EQUALS`, `GREATER`, `LESSER`, `IN` |
| **Date** | `EQUALS`, `NOT EQUALS`, `GREATER`, `LESSER` |
| **Keyword** | `EQUALS`, `NOT EQUALS`, `IN` |

### Tracking Method Values

```
NONE, IP, DNSNAME, NETBIOS, INSTANCE_ID, QAGENT, PASSIVE_SENSOR,
SHODAN, EASM, WEBHOOK, SERVICE_NOW, ACTIVE_DIRECTORY, GCP_INSTANCE_ID,
ICS_OCA, BMC_HELIX
```

## Command-Line Parameters

### Authentication

| Parameter | Short | Description |
|-----------|-------|-------------|
| `--username` | `-u` | Qualys API username (or set `QUALYS_USERNAME` env var) |
| `--password` | `-p` | Qualys API password (or set `QUALYS_PASSWORD` env var) |
| `--platform` | | Qualys platform: `US1`, `US2`, `US3`, `US4`, `EU1`, `EU2`, `IN1`, `CA1`, `AE1`, `UK1` (default: `US1`) |
| `--base-url` | | Custom API base URL (overrides `--platform`) |

### Filters

| Parameter | Short | Description |
|-----------|-------|-------------|
| `--filter` | `-f` | Add filter in format `field:operator:value` (can be repeated) |
| `--max` | | Maximum number of assets to retrieve (default: `0` = unlimited) |

### Duplicate Detection

| Parameter | Short | Description |
|-----------|-------|-------------|
| `--check` | `-c` | Criteria to check: `all` or comma-separated list of `ip,hostname,name,netbios,mac,fqdn` (default: `all`) |

### Output

| Parameter | Short | Description |
|-----------|-------|-------------|
| `--output` | `-o` | Export full results to JSON file |
| `--csv` | | Export all assets to CSV file |
| `--csv-duplicates` | | Export only duplicate assets to CSV file |
| `--compact` | | Compact output with less details per asset |
| `--quiet` | `-q` | Suppress detailed output (show summary only) |
| `--debug` | `-d` | Debug mode - show API requests and responses |

### Parameter Examples

```bash
# Authentication
-u myuser -p 'mypassword'
--username myuser --password 'mypassword'
--platform US4
--base-url "https://qualysapi.custom.com"

# Filters
--filter "tagName:CONTAINS:Production"
--filter "os:EQUALS:Windows" --filter "trackingMethod:EQUALS:QAGENT"
--max 1000

# Duplicate detection
--check all
--check ip,hostname
--check name,fqdn,mac

# Output
--output results.json
--csv all_assets.csv
--csv-duplicates dupes.csv
--compact
--quiet
--debug
```

## Usage Examples

### Basic - Find All Duplicates (No Filter)

```bash
python qualys_duplicate_finder.py \
    -u YOUR_USERNAME \
    -p 'YOUR_PASSWORD' \
    --platform US4
```

### Filter by Tag Name

```bash
# Assets tagged with "Tenable"
python qualys_duplicate_finder.py --platform US4 \
    --filter "tagName:CONTAINS:Tenable"

# Assets tagged with "Production"
python qualys_duplicate_finder.py --platform US4 \
    --filter "tagName:EQUALS:Production"
```

### Filter by Operating System

```bash
# Windows assets
python qualys_duplicate_finder.py --platform US4 \
    --filter "os:CONTAINS:Windows"

# Linux assets
python qualys_duplicate_finder.py --platform US4 \
    --filter "os:CONTAINS:Linux"
```

### Filter by Tracking Method

```bash
# Cloud Agent tracked assets
python qualys_duplicate_finder.py --platform US4 \
    --filter "trackingMethod:EQUALS:QAGENT"

# IP tracked assets
python qualys_duplicate_finder.py --platform US4 \
    --filter "trackingMethod:EQUALS:IP"
```

### Multiple Filters (AND Logic)

```bash
# Production Linux servers
python qualys_duplicate_finder.py --platform US4 \
    --filter "tagName:CONTAINS:Production" \
    --filter "os:CONTAINS:Linux"

# Windows assets with Cloud Agent
python qualys_duplicate_finder.py --platform US4 \
    --filter "os:CONTAINS:Windows" \
    --filter "trackingMethod:EQUALS:QAGENT"
```

### Check Specific Duplicate Criteria

```bash
# Check only IP and hostname duplicates
python qualys_duplicate_finder.py --platform US4 \
    --filter "tagName:CONTAINS:Servers" \
    --check ip,hostname

# Check only name duplicates
python qualys_duplicate_finder.py --platform US4 \
    --check name
```

### Export Results

```bash
# Export to JSON
python qualys_duplicate_finder.py --platform US4 \
    --filter "tagName:EQUALS:Servers" \
    --output results.json

# Export all assets to CSV
python qualys_duplicate_finder.py --platform US4 \
    --csv all_assets.csv

# Export only duplicates to CSV
python qualys_duplicate_finder.py --platform US4 \
    --csv-duplicates duplicates_only.csv

# All exports
python qualys_duplicate_finder.py --platform US4 \
    --filter "os:CONTAINS:Windows" \
    --output results.json \
    --csv assets.csv \
    --csv-duplicates duplicates.csv
```

### Limit Results

```bash
# Retrieve maximum 500 assets
python qualys_duplicate_finder.py --platform US4 \
    --filter "os:CONTAINS:Windows" \
    --max 500
```

### Output Options

```bash
# Compact output (less details)
python qualys_duplicate_finder.py --platform US4 \
    --compact

# Quiet mode (summary only)
python qualys_duplicate_finder.py --platform US4 \
    --quiet --output results.json

# Debug mode (show API requests/responses)
python qualys_duplicate_finder.py --platform US4 \
    --debug
```

## Output Example

```
Qualys CSAM Duplicate Asset Finder
==================================================
Platform: US4
Base URL: https://qualysapi.qg4.apps.qualys.com
Filters:
  - tagName CONTAINS 'Tenable'
Max assets: Unlimited
Check criteria: all

Fetching assets...
  Retrieved 100 assets so far...
  Retrieved 150 assets so far...
Total assets retrieved: 150

================================================================================
DUPLICATE ASSETS REPORT
================================================================================

----------------------------------------
Duplicates BY IP
Groups: 3
----------------------------------------

  [192.168.1.100] - 2 assets:
    • ID: 12345
      Name: server-01
      IP: 192.168.1.100
      Hostname: server-01.example.com
      OS: Windows Server 2019
      Tracking: QAGENT
      Created: 2024-01-15T10:30:00Z
      Tags: Tenable, Production

    • ID: 12346
      Name: server-01-old
      IP: 192.168.1.100
      Hostname: server-01.example.com
      OS: Windows Server 2019
      Tracking: IP
      Created: 2024-02-20T14:45:00Z
      Tags: Tenable

================================================================================
SUMMARY
  Duplicate groups found: 5
  Total duplicate assets: 8
================================================================================

==================================================
STATISTICS
==================================================
Total assets retrieved: 150
Duplicates by_ip: 3
Duplicates by_hostname: 5
Duplicates by_name: 2
Duplicates by_netbios: 1
Duplicates by_mac: 0
Duplicates by_fqdn: 4
```

## Qualys Platforms

| Platform | Region | API URL |
|----------|--------|---------|
| US1 | US Platform 1 | https://qualysapi.qualys.com |
| US2 | US Platform 2 | https://qualysapi.qg2.apps.qualys.com |
| US3 | US Platform 3 | https://qualysapi.qg3.apps.qualys.com |
| US4 | US Platform 4 | https://qualysapi.qg4.apps.qualys.com |
| EU1 | EU Platform 1 | https://qualysapi.qualys.eu |
| EU2 | EU Platform 2 | https://qualysapi.qg2.apps.qualys.eu |
| IN1 | India | https://qualysapi.qg1.apps.qualys.in |
| CA1 | Canada | https://qualysapi.qg1.apps.qualys.ca |
| AE1 | UAE | https://qualysapi.qg1.apps.qualys.ae |
| UK1 | UK | https://qualysapi.qg1.apps.qualys.co.uk |

Find your platform: Log in to Qualys → Help → About → Security Operations Center (SOC)

## Troubleshooting

### No Assets Found

1. Run without filters first to verify connectivity
2. Use `--debug` to see API request/response
3. Check filter syntax: `field:operator:value`
4. Verify field names are correct (case-sensitive)

### Authentication Errors

- Verify username and password
- Check API access is enabled for your account
- Ensure correct platform is selected

### Invalid Filter Errors

- Check operator is valid for field type
- Use `EQUALS` instead of `CONTAINS` for keyword fields
- Verify field name exists (see Available Filter Fields)

### Rate Limiting

- Script handles pagination automatically
- Use `--max` to limit results during testing
- Run during off-peak hours for large datasets

## API Reference

- **Endpoint**: `/qps/rest/2.0/search/am/hostasset`
- **Method**: POST
- **Authentication**: Basic Auth
- **Documentation**: [Qualys Asset Management & Tagging API User Guide](https://www.qualys.com/documentation/)

## License

This script is provided as-is for use with the Qualys CSAM API.
