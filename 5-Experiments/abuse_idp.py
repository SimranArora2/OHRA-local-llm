"""
Script to request AbuseIDP info for all collected ip addresses
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any

import pandas as pd
import requests
from requests.exceptions import ConnectTimeout, RequestException


class InfoRequester:
    """
    Class that requests information.
    More efficient and secure as this way info
    only has to be set once during initialization
    """

    def __init__(self, api_key: str, max_retries: int = 3, retry_delay: float = 1.0):
        self.__url = "https://api.abuseipdb.com/api/v2/check"
        self.__headers = {"Accept": "application/json", "Key": api_key}
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def get_info(self, ip: str) -> Dict[str, Any]:
        """
        Helper function to request info for a given ip with retry logic
        """
        querystring = {
            "ipAddress": ip.strip(),
        }

        for attempt in range(self.max_retries + 1):
            try:
                response = requests.request(
                    method="GET",
                    url=self.__url,
                    headers=self.__headers,
                    params=querystring,
                    timeout=10,
                )

                # Check if the response was successful
                response.raise_for_status()

                decoded_response = response.json()
                return {"status": "success", "data": decoded_response}

            except ConnectTimeout:
                if attempt < self.max_retries:
                    print(
                        f"  Timeout for {ip}, retrying in {self.retry_delay}s... (attempt {attempt + 1}/{self.max_retries})"
                    )
                    time.sleep(self.retry_delay)
                    continue
                else:
                    print(
                        f"  Failed to get info for {ip} after {self.max_retries} retries (timeout)"
                    )
                    return {
                        "status": "timeout_error",
                        "error": "Connection timeout after retries",
                        "ip": ip,
                    }

            except RequestException as e:
                if attempt < self.max_retries:
                    print(
                        f"  Request error for {ip}, retrying in {self.retry_delay}s... (attempt {attempt + 1}/{self.max_retries})"
                    )
                    time.sleep(self.retry_delay)
                    continue
                else:
                    print(
                        f"  Failed to get info for {ip} after {self.max_retries} retries (request error)"
                    )
                    return {"status": "request_error", "error": str(e), "ip": ip}

            except json.JSONDecodeError as e:
                print(f"  JSON decode error for {ip}: {e}")
                return {
                    "status": "json_error",
                    "error": f"JSON decode error: {str(e)}",
                    "ip": ip,
                }

            except Exception as e:
                print(f"  Unexpected error for {ip}: {e}")
                return {
                    "status": "unknown_error",
                    "error": f"Unexpected error: {str(e)}",
                    "ip": ip,
                }


def load_existing_results(outpath: str) -> Dict[str, Any]:
    """
    Load existing results to avoid re-requesting data
    """
    if Path(outpath).exists():
        try:
            with open(outpath, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            print(f"Warning: Could not load existing results from {outpath}")
            return {}
    return {}


def save_results(results: Dict[str, Any], outpath: str, backup: bool = True):
    """
    Save results with optional backup
    """
    if backup and Path(outpath).exists():
        backup_path = f"{outpath}.backup"
        Path(outpath).rename(backup_path)
        print(f"Created backup: {backup_path}")

    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, sort_keys=True)


def main(path: str, outpath: str, apikey: str):
    """
    main entry point of this script
    """
    # read data
    print(f"Loading data from {path}...")
    try:
        df = pd.read_excel(path, index_col=0)
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        sys.exit(1)

    print(f"Found {len(df)} IP addresses to process")

    # Load existing results to avoid duplicate requests
    existing_results = load_existing_results(outpath)
    print(f"Loaded {len(existing_results)} existing results")

    # init requester with apikey
    rq = InfoRequester(apikey)

    # Track statistics
    total_ips = len(df)
    successful_requests = 0
    failed_requests = 0
    skipped_requests = 0

    results = existing_results.copy()

    # Process each IP address
    for idx, (row_idx, row) in enumerate(df.iterrows(), 1):
        ip = str(row["ip"]).strip()

        # Skip if we already have results for this IP
        if ip in results and results[ip].get("status") == "success":
            skipped_requests += 1
            print(f"[{idx}/{total_ips}] Skipping {ip} (already processed)")
            continue

        print(f"[{idx}/{total_ips}] Processing {ip}...")

        # Request info for this IP
        info = rq.get_info(ip)
        results[ip] = info

        if info["status"] == "success":
            successful_requests += 1
            print(f"  ✓ Success")
        else:
            failed_requests += 1
            print(f"  ✗ Failed: {info.get('error', 'Unknown error')}")

        # Save results periodically (every 10 requests) to avoid data loss
        if idx % 10 == 0:
            save_results(results, outpath, backup=False)
            print(
                f"  Saved intermediate results ({successful_requests} successful, {failed_requests} failed, {skipped_requests} skipped)"
            )

    # Final save
    print(f"\nSaving final results to {outpath}...")
    save_results(results, outpath)

    # Print summary
    print(f"\n=== SUMMARY ===")
    print(f"Total IPs processed: {total_ips}")
    print(f"Successful requests: {successful_requests}")
    print(f"Failed requests: {failed_requests}")
    print(f"Skipped (already processed): {skipped_requests}")
    print(
        f"Success rate: {(successful_requests / (successful_requests + failed_requests) * 100):.1f}%"
        if (successful_requests + failed_requests) > 0
        else "N/A"
    )

    # Show failed IPs for retry
    failed_ips = [ip for ip, data in results.items() if data.get("status") != "success"]
    if failed_ips:
        print(f"\nFailed IPs ({len(failed_ips)}):")
        for ip in failed_ips[:10]:  # Show first 10 failed IPs
            print(f"  - {ip}: {results[ip].get('error', 'Unknown error')}")
        if len(failed_ips) > 10:
            print(f"  ... and {len(failed_ips) - 10} more")

    print("Done!")


if __name__ == "__main__":
    # read the api secret as the first argument
    try:
        api_secret = sys.argv[1]
    except IndexError:
        print("ERROR - Provide the api secret as the first argument!")
        print("Usage: python abuse_idp.py <API_KEY>")
        sys.exit(1)

    main("connections_info.xlsx", "abuse_ip_info.json", api_secret)
