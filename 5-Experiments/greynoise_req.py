#!/usr/bin/env python3
"""
GreyNoise Community API IP Lookup Script

This script queries the GreyNoise Community API for IP information from an Excel file.
Usage: python greynoise_lookup.py <API_KEY>

The script reads IPs from "Unreported_ips.xlsx" (column "IP") and caches results
to avoid duplicate API calls on subsequent runs.
"""

import sys
import requests
import json
import time
import os
from typing import List, Dict, Any, Set
import pandas as pd


def validate_ip(ip: str) -> bool:
    """Basic IP address validation."""
    try:
        parts = str(ip).strip().split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not (0 <= int(part) <= 255):
                return False
        return True
    except (ValueError, AttributeError):
        return False


def load_cached_results(
    cache_file: str = "greynoise_cache.json",
) -> Dict[str, Dict[str, Any]]:
    """
    Load previously cached results from JSON file.

    Returns:
        Dictionary with IP addresses as keys and their results as values
    """
    if not os.path.exists(cache_file):
        print(f"No cache file found ({cache_file}). Starting fresh.")
        return {}

    try:
        with open(cache_file, "r") as f:
            cached_data = json.load(f)

        # Convert list format to dict format if needed (backwards compatibility)
        if isinstance(cached_data, list):
            cache_dict = {}
            for item in cached_data:
                if "ip" in item:
                    cache_dict[item["ip"]] = item
            print(f"Loaded {len(cache_dict)} cached results from {cache_file}")
            return cache_dict
        elif isinstance(cached_data, dict):
            print(f"Loaded {len(cached_data)} cached results from {cache_file}")
            return cached_data
        else:
            print(f"Warning: Invalid cache file format. Starting fresh.")
            return {}

    except (json.JSONDecodeError, KeyError) as e:
        print(f"Warning: Could not read cache file ({e}). Starting fresh.")
        return {}
    except Exception as e:
        print(f"Warning: Unexpected error reading cache ({e}). Starting fresh.")
        return {}


def save_cached_results(
    cache_dict: Dict[str, Dict[str, Any]], cache_file: str = "greynoise_cache.json"
):
    """Save results to cache file."""
    try:
        with open(cache_file, "w") as f:
            json.dump(cache_dict, f, indent=2)
        print(f"Results cached to {cache_file}")
    except Exception as e:
        print(f"Warning: Could not save cache file - {str(e)}")


def load_ips_from_excel(filename: str = "Unreported_ips.xlsx") -> List[str]:
    """
    Load IP addresses from Excel file.

    Returns:
        List of valid IP addresses
    """
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

    try:
        # Read Excel file
        df = pd.read_excel(filename)

        # Check if 'IP' column exists
        if "IP" not in df.columns:
            print(f"Error: Column 'IP' not found in {filename}")
            print(f"Available columns: {list(df.columns)}")
            sys.exit(1)

        # Extract IP addresses and remove duplicates/nulls
        ips = df["IP"].dropna().astype(str).unique().tolist()

        # Validate IP addresses
        valid_ips = []
        invalid_count = 0

        for ip in ips:
            ip = str(ip).strip()
            if validate_ip(ip):
                valid_ips.append(ip)
            else:
                invalid_count += 1
                print(f"⚠️  Skipping invalid IP: {ip}")

        print(f"Loaded {len(valid_ips)} valid IP addresses from {filename}")
        if invalid_count > 0:
            print(f"Skipped {invalid_count} invalid IP addresses")

        return valid_ips

    except Exception as e:
        print(f"Error reading Excel file: {str(e)}")
        sys.exit(1)


def get_ips_to_query(
    all_ips: List[str], cached_results: Dict[str, Dict[str, Any]]
) -> List[str]:
    """
    Determine which IPs need to be queried (not in cache or failed previously).
    IPs that are "not found" in GreyNoise are also considered successfully processed.

    Returns:
        List of IP addresses that need to be queried
    """
    ips_to_query = []
    cached_successful = 0
    cached_not_found = 0
    cached_failed = 0

    for ip in all_ips:
        if ip in cached_results:
            result = cached_results[ip]
            if result.get("success", False):
                # Check if this is a "not found" result
                if (
                    result.get("data", {}).get("message")
                    == "IP not found in GreyNoise dataset"
                ):
                    cached_not_found += 1
                else:
                    cached_successful += 1
                # Don't re-query either successful results or "not found" results
            else:
                # Re-query failed attempts (network errors, API errors, etc.)
                cached_failed += 1
                ips_to_query.append(ip)
        else:
            ips_to_query.append(ip)

    print(f"Cache summary:")
    print(
        f"  - {cached_successful} IPs already successfully queried (found in GreyNoise)"
    )
    print(
        f"  - {cached_not_found} IPs confirmed not in GreyNoise database (won't re-query)"
    )
    print(f"  - {cached_failed} IPs had previous failures (will retry)")
    print(f"  - {len(ips_to_query)} IPs need to be queried")

    return ips_to_query


def query_greynoise_api(api_key: str, ip: str) -> Dict[str, Any]:
    """
    Query GreyNoise Community API for a single IP address.

    Args:
        api_key: GreyNoise API key
        ip: IP address to query

    Returns:
        Dictionary containing API response or error information
    """
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": api_key, "User-Agent": "GreyNoise-Community-Script/1.0"}

    try:
        print(f"Querying IP: {ip}...")
        response = requests.get(url, headers=headers, timeout=30)

        # Check if request was successful
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "success": True,
                "data": data,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        elif response.status_code == 404:
            return {
                "ip": ip,
                "success": True,
                "data": {"message": "IP not found in GreyNoise dataset"},
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        elif response.status_code == 401:
            return {
                "ip": ip,
                "success": False,
                "error": "Invalid API key or unauthorized access",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        elif response.status_code == 429:
            return {
                "ip": ip,
                "success": False,
                "error": "Rate limit exceeded - try again later",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        else:
            return {
                "ip": ip,
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    except requests.exceptions.Timeout:
        return {
            "ip": ip,
            "success": False,
            "error": "Request timeout - API may be unavailable",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    except requests.exceptions.ConnectionError:
        return {
            "ip": ip,
            "success": False,
            "error": "Connection error - check internet connection",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    except requests.exceptions.RequestException as e:
        return {
            "ip": ip,
            "success": False,
            "error": f"Request error: {str(e)}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    except json.JSONDecodeError:
        return {
            "ip": ip,
            "success": False,
            "error": "Invalid JSON response from API",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        return {
            "ip": ip,
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


def format_result(result: Dict[str, Any]) -> str:
    """Format the API result for display."""
    if not result["success"]:
        return f"❌ {result['ip']}: {result['error']}"

    data = result["data"]

    # Handle case where IP is not found
    if "message" in data:
        return f"ℹ️  {result['ip']}: {data['message']}"

    # Format successful response
    output = f"✅ {result['ip']}:\n"

    # Common fields in GreyNoise Community API response
    fields_to_show = [
        ("noise", "Noise"),
        ("riot", "Riot"),
        ("classification", "Classification"),
        ("name", "Name"),
        ("link", "Link"),
        ("last_seen", "Last Seen"),
        ("message", "Message"),
    ]

    for field, display_name in fields_to_show:
        if field in data and data[field] is not None:
            output += f"   {display_name}: {data[field]}\n"

    return output.rstrip()


def export_final_results(
    cache_dict: Dict[str, Dict[str, Any]],
    output_file: str = "greynoise_final_results.json",
):
    """Export all results in a clean format for final use."""
    try:
        # Convert cache format to clean results format
        final_results = []
        for ip, result in cache_dict.items():
            final_results.append(result)

        with open(output_file, "w") as f:
            json.dump(final_results, f, indent=2)
        print(f"Final results exported to: {output_file}")

        # Also create a CSV summary for easy viewing
        csv_file = output_file.replace(".json", "_summary.csv")
        try:
            summary_data = []
            for result in final_results:
                if result["success"] and "data" in result:
                    data = result["data"]
                    summary_data.append(
                        {
                            "IP": result["ip"],
                            "Status": (
                                "Found in GreyNoise"
                                if data.get("message")
                                != "IP not found in GreyNoise dataset"
                                else "Not in GreyNoise"
                            ),
                            "Noise": data.get("noise", "N/A"),
                            "Riot": data.get("riot", "N/A"),
                            "Classification": data.get("classification", "N/A"),
                            "Name": data.get("name", "N/A"),
                            "Last_Seen": data.get("last_seen", "N/A"),
                            "Message": data.get("message", "N/A"),
                            "Timestamp": result.get("timestamp", "N/A"),
                        }
                    )
                else:
                    summary_data.append(
                        {
                            "IP": result["ip"],
                            "Status": "Failed",
                            "Error": result.get("error", "Unknown"),
                            "Timestamp": result.get("timestamp", "N/A"),
                        }
                    )

            if summary_data:
                df = pd.DataFrame(summary_data)
                df.to_csv(csv_file, index=False)
                print(f"Summary CSV exported to: {csv_file}")

        except Exception as e:
            print(f"Warning: Could not create CSV summary - {str(e)}")

    except Exception as e:
        print(f"Warning: Could not export final results - {str(e)}")


def main():
    """Main function."""
    print("GreyNoise Community API IP Lookup Tool")
    print("=" * 40)

    # Check for API key argument
    if len(sys.argv) != 2:
        print("Usage: python greynoise_lookup.py <API_KEY>")
        print("The script will read IPs from 'Unreported_ips.xlsx'")
        sys.exit(1)

    api_key = sys.argv[1]
    cache_file = "greynoise_cache.json"

    # Load IP addresses from Excel file
    print("Loading IP addresses from Excel file...")
    all_ips = load_ips_from_excel()

    if not all_ips:
        print("No valid IP addresses found in Excel file.")
        sys.exit(0)

    # Load cached results
    print("\nChecking for cached results...")
    cached_results = load_cached_results(cache_file)

    # Determine which IPs need to be queried
    ips_to_query = get_ips_to_query(all_ips, cached_results)

    if not ips_to_query:
        print("\n✅ All IP addresses have already been successfully queried!")
        export_final_results(cached_results)
        sys.exit(0)

    print(f"\nQuerying {len(ips_to_query)} IP address(es)...")
    print("-" * 40)

    # Query each IP with error handling
    new_results = 0
    for i, ip in enumerate(ips_to_query, 1):
        try:
            result = query_greynoise_api(api_key, ip)
            cached_results[ip] = result
            new_results += 1

            # Print result immediately
            print(format_result(result))

            # Save cache after each successful query to avoid losing data
            if i % 5 == 0:  # Save every 5 queries
                save_cached_results(cached_results, cache_file)

            # Add delay between requests to be respectful to the API
            if i < len(ips_to_query):
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            print("Saving current progress...")
            save_cached_results(cached_results, cache_file)
            break
        except Exception as e:
            # This should not happen due to error handling in query_greynoise_api,
            # but added as extra safety
            print(f"❌ {ip}: Unexpected error - {str(e)}")
            cached_results[ip] = {
                "ip": ip,
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    # Final save of cache
    save_cached_results(cached_results, cache_file)

    # Summary
    print("\n" + "=" * 40)
    total_ips = len(all_ips)
    successful_found = sum(
        1
        for r in cached_results.values()
        if r.get("success", False)
        and r.get("data", {}).get("message") != "IP not found in GreyNoise dataset"
    )
    not_found = sum(
        1
        for r in cached_results.values()
        if r.get("success", False)
        and r.get("data", {}).get("message") == "IP not found in GreyNoise dataset"
    )
    failed = sum(1 for r in cached_results.values() if not r.get("success", False))

    print(f"Overall Summary:")
    print(f"  - Total IPs in Excel file: {total_ips}")
    print(f"  - Found in GreyNoise: {successful_found}")
    print(f"  - Not in GreyNoise database: {not_found}")
    print(f"  - Failed queries: {failed}")
    print(f"  - New queries in this run: {new_results}")

    # Export final results
    export_final_results(cached_results)

    if failed > 0:
        print(
            f"\n⚠️  {failed} IPs failed. Run the script again to retry failed queries."
        )
    else:
        print(
            f"\n✅ All IPs have been processed! ({successful_found} found, {not_found} not in database)"
        )


if __name__ == "__main__":
    main()
