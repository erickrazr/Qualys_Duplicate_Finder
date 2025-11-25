#!/usr/bin/env python3
"""
Qualys CSAM Duplicate Asset Finder

A generic tool to query the Qualys Asset Management API and identify 
duplicate assets based on various criteria (IP, hostname, name, MAC, etc.)

Supports flexible filtering to narrow down asset searches.

Based on Qualys Asset Management & Tagging API v2 documentation.
"""

import requests
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import argparse
import json
import sys
import os
from urllib.parse import urljoin


@dataclass
class Asset:
    """Represents a Qualys Host Asset"""
    id: int
    name: str
    dns_hostname: Optional[str] = None
    address: Optional[str] = None
    netbios_name: Optional[str] = None
    os: Optional[str] = None
    tracking_method: Optional[str] = None
    fqdn: Optional[str] = None
    mac_addresses: List[str] = field(default_factory=list)
    created: Optional[str] = None
    modified: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    source_type: Optional[str] = None
    
    def __hash__(self):
        return hash(self.id)


class QualysCSAMClient:
    """Client for interacting with Qualys CSAM API"""
    
    # Default API base URLs for different Qualys platforms
    PLATFORM_URLS = {
        'US1': 'https://qualysapi.qualys.com',
        'US2': 'https://qualysapi.qg2.apps.qualys.com',
        'US3': 'https://qualysapi.qg3.apps.qualys.com',
        'US4': 'https://qualysapi.qg4.apps.qualys.com',
        'EU1': 'https://qualysapi.qualys.eu',
        'EU2': 'https://qualysapi.qg2.apps.qualys.eu',
        'IN1': 'https://qualysapi.qg1.apps.qualys.in',
        'CA1': 'https://qualysapi.qg1.apps.qualys.ca',
        'AE1': 'https://qualysapi.qg1.apps.qualys.ae',
        'UK1': 'https://qualysapi.qg1.apps.qualys.co.uk',
    }
    
    def __init__(self, username: str, password: str, platform: str = 'US1', 
                 base_url: Optional[str] = None):
        """
        Initialize the Qualys CSAM API client.
        
        Args:
            username: Qualys API username
            password: Qualys API password
            platform: Qualys platform identifier (US1, US2, EU1, etc.)
            base_url: Custom base URL (overrides platform selection)
        """
        self.username = username
        self.password = password
        
        if base_url:
            self.base_url = base_url.rstrip('/')
        else:
            self.base_url = self.PLATFORM_URLS.get(platform.upper(), self.PLATFORM_URLS['US1'])
        
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({
            'X-Requested-With': 'Python Script',
            'Cache-Control': 'no-cache'
        })
    
    def _make_request(self, method: str, endpoint: str, data: Optional[str] = None,
                      content_type: str = 'text/xml') -> requests.Response:
        """Make an API request to Qualys."""
        url = urljoin(self.base_url, endpoint)
        headers = {'Content-Type': content_type}
        
        response = self.session.request(
            method=method,
            url=url,
            data=data,
            headers=headers
        )
        
        if not response.ok:
            error_msg = f"HTTP {response.status_code}"
            try:
                error_msg += f"\nResponse: {response.text}"
            except:
                pass
            raise requests.exceptions.HTTPError(error_msg, response=response)
        
        return response
    
    def search_host_assets(self, filter_criteria: List[Dict[str, str]], 
                           limit: int = 100, offset: int = 1,
                           fields: Optional[List[str]] = None,
                           debug: bool = False) -> Dict[str, Any]:
        """
        Search for host assets using the CSAM API.
        
        Args:
            filter_criteria: List of filter criteria dictionaries with 
                           'field', 'operator', and 'value' keys
            limit: Maximum number of results per request (max 100)
            offset: Starting offset for pagination (1-based)
            fields: Optional list of fields to return
            debug: Print debug information
            
        Returns:
            Dictionary containing response data
        """
        endpoint = '/qps/rest/2.0/search/am/hostasset'
        
        xml_request = self._build_search_request(filter_criteria, limit, offset)
        
        if debug:
            print(f"\n[DEBUG] Request URL: {self.base_url}{endpoint}")
            print(f"[DEBUG] Request Body:\n{xml_request}\n")
        
        if fields:
            endpoint += f"?fields={','.join(fields)}"
        
        response = self._make_request('POST', endpoint, data=xml_request)
        
        if debug:
            print(f"[DEBUG] Response:\n{response.text[:2000]}...\n")
        
        return self._parse_search_response(response.text)
    
    def _build_search_request(self, filter_criteria: List[Dict[str, str]], 
                              limit: int, offset: int) -> str:
        """Build XML request body for search API.
        
        Note: Qualys API uses 1-based indexing for startFromOffset.
        """
        if filter_criteria:
            criteria_xml = "\n    <filters>"
            for criterion in filter_criteria:
                criteria_xml += f'\n        <Criteria field="{criterion["field"]}" operator="{criterion["operator"]}">{criterion["value"]}</Criteria>'
            criteria_xml += "\n    </filters>"
        else:
            criteria_xml = ""
        
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>{criteria_xml}
    <preferences>
        <startFromOffset>{offset}</startFromOffset>
        <limitResults>{limit}</limitResults>
    </preferences>
</ServiceRequest>'''
    
    def _parse_search_response(self, xml_response: str) -> Dict[str, Any]:
        """Parse XML response from search API."""
        root = ET.fromstring(xml_response)
        
        result = {
            'response_code': '',
            'count': 0,
            'has_more_records': False,
            'last_id': None,
            'assets': []
        }
        
        response_code = root.find('responseCode')
        if response_code is not None:
            result['response_code'] = response_code.text
        
        count = root.find('count')
        if count is not None:
            result['count'] = int(count.text)
        
        has_more = root.find('hasMoreRecords')
        if has_more is not None:
            result['has_more_records'] = has_more.text.lower() == 'true'
        
        last_id = root.find('lastId')
        if last_id is not None:
            result['last_id'] = int(last_id.text)
        
        data = root.find('data')
        if data is not None:
            for host_asset in data.findall('HostAsset'):
                asset = self._parse_host_asset(host_asset)
                result['assets'].append(asset)
        
        return result
    
    def _parse_host_asset(self, element: ET.Element) -> Asset:
        """Parse a HostAsset XML element into an Asset object."""
        def get_text(tag_name: str) -> Optional[str]:
            el = element.find(tag_name)
            return el.text if el is not None else None
        
        asset = Asset(
            id=int(get_text('id') or 0),
            name=get_text('name') or get_text('n') or '',
            dns_hostname=get_text('dnsHostName'),
            address=get_text('address'),
            netbios_name=get_text('netbiosName'),
            os=get_text('os'),
            tracking_method=get_text('trackingMethod'),
            fqdn=get_text('fqdn'),
            created=get_text('created'),
            modified=get_text('modified')
        )
        
        # Parse tags
        tags_list = element.find('.//tags/list')
        if tags_list is not None:
            for tag_simple in tags_list.findall('TagSimple'):
                tag_name = tag_simple.find('name')
                if tag_name is None:
                    tag_name = tag_simple.find('n')
                if tag_name is not None and tag_name.text:
                    asset.tags.append(tag_name.text)
        
        # Parse MAC addresses from network interfaces
        for interface in element.findall('.//networkInterface/list/HostAssetInterface'):
            mac = interface.find('macAddress')
            if mac is not None and mac.text:
                asset.mac_addresses.append(mac.text.lower())
        
        # Parse source info
        source_info = element.find('.//sourceInfo/list')
        if source_info is not None:
            for child in source_info:
                if child.tag != 'AssetSource' and child.text:
                    asset.source_type = child.tag.replace('AssetSourceSimple', '').replace('Simple', '')
        
        return asset
    
    def get_all_assets_with_filter(self, filter_criteria: List[Dict[str, str]], 
                                   page_size: int = 100,
                                   debug: bool = False,
                                   max_assets: int = 0) -> List[Asset]:
        """
        Get all assets matching the filter criteria, handling pagination.
        
        Args:
            filter_criteria: List of filter criteria
            page_size: Number of results per page (max 100)
            debug: Print debug information
            max_assets: Maximum number of assets to retrieve (0 = unlimited)
            
        Returns:
            List of all matching assets
        """
        all_assets = []
        offset = 1  # Qualys API uses 1-based indexing
        
        print(f"Fetching assets...")
        
        while True:
            result = self.search_host_assets(
                filter_criteria=filter_criteria,
                limit=page_size,
                offset=offset,
                debug=debug
            )
            
            if result['response_code'] != 'SUCCESS':
                raise Exception(f"API Error: {result['response_code']}")
            
            all_assets.extend(result['assets'])
            print(f"  Retrieved {len(all_assets)} assets so far...")
            
            # Check if we've hit the max limit
            if max_assets > 0 and len(all_assets) >= max_assets:
                all_assets = all_assets[:max_assets]
                break
            
            if not result['has_more_records']:
                break
            
            offset += page_size
            debug = False  # Only debug first request
        
        print(f"Total assets retrieved: {len(all_assets)}")
        return all_assets


class DuplicateFinder:
    """Finds duplicate assets based on various criteria"""
    
    def __init__(self, assets: List[Asset]):
        self.assets = assets
    
    def find_by_field(self, field_name: str, getter) -> Dict[str, List[Asset]]:
        """Generic method to find duplicates by any field.

        Only returns groups where there are multiple DIFFERENT assets (by ID)
        sharing the same field value.
        """
        field_map = defaultdict(set)  # Use set to avoid duplicate asset IDs
        for asset in self.assets:
            value = getter(asset)
            if value:
                if isinstance(value, list):
                    for v in value:
                        field_map[v.lower() if isinstance(v, str) else v].add(asset)
                else:
                    field_map[value.lower() if isinstance(value, str) else value].add(asset)

        # Convert sets to lists and only return groups with multiple DIFFERENT assets
        return {k: list(v) for k, v in field_map.items() if len(v) > 1}
    
    def find_by_ip(self) -> Dict[str, List[Asset]]:
        """Find duplicates by IP address."""
        return self.find_by_field('address', lambda a: a.address)
    
    def find_by_hostname(self) -> Dict[str, List[Asset]]:
        """Find duplicates by DNS hostname."""
        return self.find_by_field('dns_hostname', lambda a: a.dns_hostname)
    
    def find_by_name(self) -> Dict[str, List[Asset]]:
        """Find duplicates by asset name."""
        return self.find_by_field('name', lambda a: a.name)
    
    def find_by_netbios(self) -> Dict[str, List[Asset]]:
        """Find duplicates by NetBIOS name."""
        return self.find_by_field('netbios_name', lambda a: a.netbios_name)
    
    def find_by_mac(self) -> Dict[str, List[Asset]]:
        """Find duplicates by MAC address."""
        return self.find_by_field('mac_addresses', lambda a: a.mac_addresses)
    
    def find_by_fqdn(self) -> Dict[str, List[Asset]]:
        """Find duplicates by FQDN."""
        return self.find_by_field('fqdn', lambda a: a.fqdn)
    
    def find_all_duplicates(self, criteria: List[str] = None) -> Dict[str, Dict[str, List[Asset]]]:
        """
        Find duplicates based on specified criteria.
        
        Args:
            criteria: List of criteria to check. Options: ip, hostname, name, netbios, mac, fqdn
                     If None, checks all criteria.
        """
        all_criteria = {
            'ip': self.find_by_ip,
            'hostname': self.find_by_hostname,
            'name': self.find_by_name,
            'netbios': self.find_by_netbios,
            'mac': self.find_by_mac,
            'fqdn': self.find_by_fqdn
        }
        
        if criteria is None:
            criteria = list(all_criteria.keys())
        
        return {
            f'by_{c}': all_criteria[c]()
            for c in criteria
            if c in all_criteria
        }


def print_duplicates_report(duplicates: Dict[str, Dict[str, List[Asset]]], verbose: bool = True):
    """Print a formatted report of duplicate assets."""
    print("\n" + "=" * 80)
    print("DUPLICATE ASSETS REPORT")
    print("=" * 80)
    
    total_duplicate_groups = 0
    total_duplicate_assets = 0
    
    for dup_type, dup_dict in duplicates.items():
        if dup_dict:
            print(f"\n{'-' * 40}")
            print(f"Duplicates {dup_type.replace('_', ' ').upper()}")
            print(f"Groups: {len(dup_dict)}")
            print(f"{'-' * 40}")
            
            for key, assets in sorted(dup_dict.items()):
                total_duplicate_groups += 1
                total_duplicate_assets += len(assets) - 1
                
                print(f"\n  [{key}] - {len(assets)} assets:")
                
                if verbose:
                    for asset in assets:
                        print(f"    • ID: {asset.id}")
                        print(f"      Name: {asset.name}")
                        print(f"      IP: {asset.address or 'N/A'}")
                        print(f"      Hostname: {asset.dns_hostname or 'N/A'}")
                        print(f"      OS: {asset.os or 'N/A'}")
                        print(f"      Tracking: {asset.tracking_method or 'N/A'}")
                        print(f"      Created: {asset.created or 'N/A'}")
                        if asset.tags:
                            print(f"      Tags: {', '.join(asset.tags[:5])}{'...' if len(asset.tags) > 5 else ''}")
                        print()
                else:
                    # Compact output
                    for asset in assets:
                        print(f"    • ID: {asset.id} | {asset.name} | {asset.address or 'N/A'} | {asset.tracking_method or 'N/A'}")
    
    print("\n" + "=" * 80)
    print(f"SUMMARY")
    print(f"  Duplicate groups found: {total_duplicate_groups}")
    print(f"  Total duplicate assets: {total_duplicate_assets}")
    print("=" * 80)


def export_to_json(assets: List[Asset], duplicates: Dict[str, Dict[str, List[Asset]]], 
                   filename: str):
    """Export results to JSON file."""
    output = {
        'total_assets': len(assets),
        'assets': [
            {
                'id': a.id,
                'name': a.name,
                'dns_hostname': a.dns_hostname,
                'address': a.address,
                'netbios_name': a.netbios_name,
                'os': a.os,
                'tracking_method': a.tracking_method,
                'fqdn': a.fqdn,
                'mac_addresses': a.mac_addresses,
                'created': a.created,
                'modified': a.modified,
                'tags': a.tags,
                'source_type': a.source_type
            }
            for a in assets
        ],
        'duplicates': {
            dup_type: {
                key: [{'id': a.id, 'name': a.name, 'address': a.address} for a in asset_list]
                for key, asset_list in dup_dict.items()
            }
            for dup_type, dup_dict in duplicates.items()
        }
    }
    
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults exported to: {filename}")


def export_to_csv(assets: List[Asset], filename: str):
    """Export assets to CSV file."""
    import csv
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'ID', 'Name', 'DNS Hostname', 'IP Address', 'NetBIOS Name',
            'OS', 'Tracking Method', 'FQDN', 'MAC Addresses', 'Created',
            'Modified', 'Tags', 'Source Type'
        ])
        
        for a in assets:
            writer.writerow([
                a.id,
                a.name,
                a.dns_hostname or '',
                a.address or '',
                a.netbios_name or '',
                a.os or '',
                a.tracking_method or '',
                a.fqdn or '',
                ';'.join(a.mac_addresses),
                a.created or '',
                a.modified or '',
                ';'.join(a.tags),
                a.source_type or ''
            ])
    
    print(f"Assets exported to CSV: {filename}")


def export_duplicates_csv(duplicates: Dict[str, Dict[str, List[Asset]]], filename: str):
    """Export only duplicate assets to CSV."""
    import csv
    
    # Collect all unique duplicate assets
    duplicate_ids = set()
    for dup_dict in duplicates.values():
        for assets in dup_dict.values():
            for asset in assets:
                duplicate_ids.add(asset.id)
    
    # Get unique assets that are duplicates
    seen = set()
    duplicate_assets = []
    for dup_type, dup_dict in duplicates.items():
        for key, assets in dup_dict.items():
            for asset in assets:
                if asset.id not in seen:
                    seen.add(asset.id)
                    duplicate_assets.append((dup_type, key, asset))
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Duplicate Type', 'Duplicate Key', 'ID', 'Name', 'DNS Hostname', 
            'IP Address', 'Tracking Method', 'Created', 'Tags'
        ])
        
        for dup_type, key, a in duplicate_assets:
            writer.writerow([
                dup_type,
                key,
                a.id,
                a.name,
                a.dns_hostname or '',
                a.address or '',
                a.tracking_method or '',
                a.created or '',
                ';'.join(a.tags[:5])
            ])
    
    print(f"Duplicates exported to CSV: {filename}")


def parse_filter(filter_str: str) -> Dict[str, str]:
    """Parse a filter string in format 'field:operator:value'"""
    parts = filter_str.split(':', 2)
    if len(parts) != 3:
        raise ValueError(f"Invalid filter format: {filter_str}. Expected 'field:operator:value'")
    return {
        'field': parts[0],
        'operator': parts[1],
        'value': parts[2]
    }


def main():
    parser = argparse.ArgumentParser(
        description='Qualys CSAM Duplicate Asset Finder - Find duplicate assets using flexible filters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
FILTER FORMAT:
  Filters use the format: field:operator:value
  
  Examples:
    --filter "tagName:CONTAINS:Tenable"
    --filter "os:CONTAINS:Windows"
    --filter "trackingMethod:EQUALS:QAGENT"
    --filter "address:EQUALS:192.168.1.100"

AVAILABLE FILTER FIELDS:
  Basic:        id, name, os, dnsHostName, address, fqdn
  Tags:         tagId, tagName  
  Network:      netbiosName, netbiosNetworkId, networkGuid
  Tracking:     trackingMethod, qwebHostId
  Dates:        created, modified, lastVulnScan, lastComplianceScan
  Software:     installedSoftware
  Ports:        port
  
  Cloud (AWS):  region, vpcId, accountId, instanceId, availabilityZone
  Cloud (Azure): vmId, subscriptionId, location, resourceGroupName
  Cloud (GCP):  gcpInstanceId, gcpProjectId, gcpZone

AVAILABLE OPERATORS:
  Text:     CONTAINS, EQUALS, NOT EQUALS
  Integer:  EQUALS, NOT EQUALS, GREATER, LESSER, IN
  Date:     EQUALS, NOT EQUALS, GREATER, LESSER
  Keyword:  EQUALS, NOT EQUALS, IN

TRACKING METHODS:
  NONE, IP, DNSNAME, NETBIOS, INSTANCE_ID, QAGENT, PASSIVE_SENSOR,
  SHODAN, EASM, WEBHOOK, SERVICE_NOW, ACTIVE_DIRECTORY, GCP_INSTANCE_ID

DUPLICATE DETECTION CRITERIA:
  ip        - Find assets with same IP address
  hostname  - Find assets with same DNS hostname
  name      - Find assets with same name
  netbios   - Find assets with same NetBIOS name
  mac       - Find assets with same MAC address
  fqdn      - Find assets with same FQDN

EXAMPLES:
  # Find all duplicates (no filter)
  %(prog)s -u USER -p PASS --platform US4

  # Find duplicates in Tenable-tagged assets
  %(prog)s --filter "tagName:CONTAINS:Tenable"

  # Find duplicates in Windows assets
  %(prog)s --filter "os:CONTAINS:Windows"

  # Find duplicates tracked by Cloud Agent
  %(prog)s --filter "trackingMethod:EQUALS:QAGENT"

  # Multiple filters (AND logic)
  %(prog)s --filter "tagName:CONTAINS:Production" --filter "os:CONTAINS:Linux"

  # Check only IP and hostname duplicates
  %(prog)s --check ip,hostname

  # Export results
  %(prog)s --filter "tagName:EQUALS:Servers" --output results.json --csv assets.csv

  # Compact output with limit
  %(prog)s --filter "os:CONTAINS:Windows" --compact --max 500
        '''
    )
    
    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-u', '--username', 
                           default=os.environ.get('QUALYS_USERNAME'),
                           help='Qualys API username (or QUALYS_USERNAME env var)')
    auth_group.add_argument('-p', '--password', 
                           default=os.environ.get('QUALYS_PASSWORD'),
                           help='Qualys API password (or QUALYS_PASSWORD env var)')
    auth_group.add_argument('--platform', default='US1',
                           choices=['US1', 'US2', 'US3', 'US4', 'EU1', 'EU2', 'IN1', 'CA1', 'AE1', 'UK1'],
                           help='Qualys platform (default: US1)')
    auth_group.add_argument('--base-url', 
                           help='Custom API base URL (overrides platform)')
    
    # Filters
    filter_group = parser.add_argument_group('Filters')
    filter_group.add_argument('-f', '--filter', action='append', dest='filters',
                             metavar='FIELD:OPERATOR:VALUE',
                             help='Add filter (can be repeated for multiple filters)')
    filter_group.add_argument('--max', type=int, default=0, metavar='N',
                             help='Maximum assets to retrieve (0 = unlimited)')
    
    # Duplicate detection
    dup_group = parser.add_argument_group('Duplicate Detection')
    dup_group.add_argument('-c', '--check', default='all',
                          help='Criteria to check: all, or comma-separated list (ip,hostname,name,netbios,mac,fqdn)')
    
    # Output
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-o', '--output', metavar='FILE',
                             help='Export full results to JSON file')
    output_group.add_argument('--csv', metavar='FILE',
                             help='Export all assets to CSV file')
    output_group.add_argument('--csv-duplicates', metavar='FILE',
                             help='Export only duplicates to CSV file')
    output_group.add_argument('--compact', action='store_true',
                             help='Compact output (less details)')
    output_group.add_argument('-q', '--quiet', action='store_true',
                             help='Suppress detailed output (only show summary)')
    output_group.add_argument('-d', '--debug', action='store_true',
                             help='Debug mode (show API requests/responses)')
    
    args = parser.parse_args()
    
    # Validate credentials
    if not args.username or not args.password:
        print("Error: Username and password are required.")
        print("Set QUALYS_USERNAME and QUALYS_PASSWORD environment variables")
        print("or use -u and -p arguments.")
        sys.exit(1)
    
    # Parse filters
    filter_criteria = []
    if args.filters:
        for f in args.filters:
            try:
                filter_criteria.append(parse_filter(f))
            except ValueError as e:
                print(f"Error: {e}")
                sys.exit(1)
    
    # Parse duplicate check criteria
    if args.check.lower() == 'all':
        check_criteria = None  # Check all
    else:
        check_criteria = [c.strip() for c in args.check.split(',')]
    
    # Print configuration
    print(f"Qualys CSAM Duplicate Asset Finder")
    print(f"=" * 50)
    print(f"Platform: {args.platform}")
    print(f"Base URL: {args.base_url or QualysCSAMClient.PLATFORM_URLS.get(args.platform.upper())}")
    if filter_criteria:
        print(f"Filters:")
        for fc in filter_criteria:
            print(f"  - {fc['field']} {fc['operator']} '{fc['value']}'")
    else:
        print(f"Filters: None (fetching all assets)")
    print(f"Max assets: {'Unlimited' if args.max == 0 else args.max}")
    print(f"Check criteria: {args.check}")
    print()
    
    try:
        # Initialize client
        client = QualysCSAMClient(
            username=args.username,
            password=args.password,
            platform=args.platform,
            base_url=args.base_url
        )
        
        # Fetch assets
        assets = client.get_all_assets_with_filter(
            filter_criteria, 
            debug=args.debug,
            max_assets=args.max
        )
        
        if not assets:
            print("\nNo assets found matching the filter criteria.")
            print("\nTips:")
            print("  1. Run without filters to fetch all assets")
            print("  2. Use --debug to see the API request/response")
            print("  3. Check filter syntax: field:operator:value")
            sys.exit(0)
        
        # Find duplicates
        finder = DuplicateFinder(assets)
        duplicates = finder.find_all_duplicates(check_criteria)
        
        # Print report
        if not args.quiet:
            print_duplicates_report(duplicates, verbose=not args.compact)
        
        # Export results
        if args.output:
            export_to_json(assets, duplicates, args.output)
        
        if args.csv:
            export_to_csv(assets, args.csv)
        
        if args.csv_duplicates:
            export_duplicates_csv(duplicates, args.csv_duplicates)
        
        # Print summary statistics
        print(f"\n{'=' * 50}")
        print("STATISTICS")
        print(f"{'=' * 50}")
        print(f"Total assets retrieved: {len(assets)}")
        for dup_type, dup_dict in duplicates.items():
            count = sum(len(v) - 1 for v in dup_dict.values())
            print(f"Duplicates {dup_type}: {count}")
        
    except requests.exceptions.HTTPError as e:
        print(f"\nAPI Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
