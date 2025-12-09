#!/usr/bin/env python3
"""
Lightweight Domain Analysis Script
Fetches domains from ISC SANS and performs WHOIS + DNS lookups
"""

import requests
import json
import hashlib
import csv
import time
import dns.resolver
import argparse
import socket
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore, Lock
import signal
import sys

# Configuration
API_URL = "https://isc.sans.edu/api/recentdomains/today?json"
HASH_FILE = "domains_hash.txt"
OUTPUT_FILE = "domain_analysis.csv"
PROGRESS_FILE = "progress.json"
MAX_WORKERS = 4  # Very conservative for large datasets
RATE_LIMIT_DELAY = 1.0  # Increased delay
DNS_TIMEOUT = 5
WHOIS_TIMEOUT = 8
MAX_RETRIES = 2  # Minimal retries
BATCH_SAVE_SIZE = 50  # Save progress every 50 domains

# Semaphore for rate limiting
rate_limiter = Semaphore(MAX_WORKERS)
write_lock = Lock()

# Graceful shutdown handler
shutdown_flag = False

def signal_handler(sig, frame):
    global shutdown_flag
    print("\n[!] Interrupt received. Saving progress...")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def get_file_hash(content):
    """Generate MD5 hash of content"""
    return hashlib.md5(content.encode()).hexdigest()

def fetch_domains():
    """Fetch domain list from API"""
    try:
        response = requests.get(API_URL, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"[ERROR] Failed to fetch domains: {e}")
        return None

def check_if_changed(content):
    """Check if content has changed since last run"""
    current_hash = get_file_hash(content)

    if Path(HASH_FILE).exists():
        with open(HASH_FILE, 'r') as f:
            old_hash = f.read().strip()
            if old_hash == current_hash:
                return False

    with open(HASH_FILE, 'w') as f:
        f.write(current_hash)

    return True

def load_progress():
    """Load progress from file"""
    if Path(PROGRESS_FILE).exists():
        try:
            with open(PROGRESS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data.get("processed"), list):
                    data["processed"] = set(data["processed"])
                return data
        except:
            return {"processed": set()}
    return {"processed": set()}

def save_progress(progress):
    """Save progress to file"""
    try:
        with open(PROGRESS_FILE, 'w') as f:
            progress_copy = progress.copy()
            progress_copy["processed"] = list(progress_copy["processed"])
            json.dump(progress_copy, f)
    except Exception as e:
        print(f"[WARN] Failed to save progress: {e}")

def safe_whois_query(domain):
    """Safe WHOIS query with strict timeout"""
    result = {
        'registrarName': '',
        'registrarIANAID': '',
        'createdDate': '',
        'updatedDate': '',
        'expiresDate': '',
        'nameServers': '',
        'status': ''
    }

    try:
        # Try python-whois first
        import whois
        socket.setdefaulttimeout(WHOIS_TIMEOUT)
        w = whois.whois(domain)

        if w:
            result['registrarName'] = str(w.registrar or '')[:200]
            result['registrarIANAID'] = str(getattr(w, 'registrar_iana_id', '') or '')

            # Handle dates
            for date_field, key in [('creation_date', 'createdDate'),
                                    ('updated_date', 'updatedDate'),
                                    ('expiration_date', 'expiresDate')]:
                date_val = getattr(w, date_field, None)
                if date_val:
                    if isinstance(date_val, list):
                        date_val = date_val[0] if date_val else None
                    if isinstance(date_val, datetime):
                        result[key] = date_val.strftime('%Y-%m-%d')
                    elif date_val:
                        result[key] = str(date_val)[:50]

            # Name servers
            if w.name_servers:
                ns_list = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                result['nameServers'] = '|'.join([str(ns).lower() for ns in ns_list[:10] if ns])[:500]

            # Status
            if w.status:
                status_list = w.status if isinstance(w.status, list) else [w.status]
                result['status'] = '|'.join([str(s) for s in status_list[:5] if s])[:300]

    except socket.timeout:
        pass  # Silent timeout
    except Exception:
        pass  # Silent failure for other errors
    finally:
        socket.setdefaulttimeout(None)

    return result

def safe_dns_query(domain, record_type):

    """Safely query DNS with timeout"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in list(answers)[:20]]  # Limit results
    except:
        return []

def get_ip_info(ip):
    """Get IP geolocation info using ip-api.com"""
    try:
        time.sleep(0.3)  # Rate limit
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'asn': (data.get('as', '').split()[0] if data.get('as') else '')[:50],
                    'org': (data.get('org', '') or '')[:200],
                    'country': (data.get('countryCode', '') or '')[:10],
                    'region': (data.get('regionName', '') or '')[:100],
                    'city': (data.get('city', '') or '')[:100],
                    'lat': str(data.get('lat', '') or '')[:20],
                    'lon': str(data.get('lon', '') or '')[:20]
                }
    except:
        pass

    return {
        'asn': '', 'org': '', 'country': '',
        'region': '', 'city': '', 'lat': '', 'lon': ''
    }

def process_domain(domain_data):
    """Process a single domain - ultra-lightweight version"""
    if shutdown_flag:
        return None

    domain = domain_data['domainname']
    original_ip = domain_data.get('ip', '')

    # Rate limiting
    with rate_limiter:
        time.sleep(RATE_LIMIT_DELAY)

    result = {
        'domain': domain,
        'registrarName': '', 'registrarIANAID': '',
        'createdDate': '', 'updatedDate': '', 'expiresDate': '',
        'abuseEmail': '', 'nameServers': '', 'status': '',
        'registrant_name': '', 'registrant_organization': '',
        'registrant_street1': '', 'registrant_city': '',
        'registrant_state': '', 'registrant_postalCode': '',
        'registrant_country': '', 'registrant_telephone': '',
        'registrant_fax': '', 'registrant_email': '',
        'admin_name': '', 'admin_organization': '',
        'admin_street1': '', 'admin_city': '',
        'admin_state': '', 'admin_postalCode': '',
        'admin_country': '', 'admin_telephone': '',
        'admin_fax': '', 'admin_email': '',
        'tech_name': '', 'tech_organization': '',
        'tech_street1': '', 'tech_city': '',
        'tech_state': '', 'tech_postalCode': '',
        'tech_country': '', 'tech_telephone': '',
        'tech_fax': '', 'tech_email': '',
        'A_count': 0, 'A_values': '',
        'AAAA_count': 0, 'AAAA_values': '',
        'MX_count': 0, 'MX_values': '',
        'NS_count': 0, 'NS_values': '',
        'TXT_count': 0, 'TXT_values': '',
        'SOA_value': '',
        'DMARC_present': 'No', 'DMARC_value': '',
        'ip_asn': '', 'ip_org': '', 'ip_country': '',
        'ip_region': '', 'ip_city': '',
        'ip_latitude': '', 'ip_longitude': ''
    }

    # WHOIS lookup - single attempt only
    if not shutdown_flag:
        whois_data = safe_whois_query(domain)
        result.update(whois_data)

    # DNS lookups
    if shutdown_flag:
        return None

    # A records
    a_records = safe_dns_query(domain, 'A')
    result['A_count'] = len(a_records)
    result['A_values'] = '|'.join(a_records)[:500]

    # AAAA records
    aaaa_records = safe_dns_query(domain, 'AAAA')
    result['AAAA_count'] = len(aaaa_records)
    result['AAAA_values'] = '|'.join(aaaa_records)[:500]

    # MX records
    mx_records = safe_dns_query(domain, 'MX')
    result['MX_count'] = len(mx_records)
    result['MX_values'] = '|'.join(mx_records)[:500]

    # NS records
    ns_records = safe_dns_query(domain, 'NS')
    result['NS_count'] = len(ns_records)
    result['NS_values'] = '|'.join(ns_records)[:500]

    # TXT records
    txt_records = safe_dns_query(domain, 'TXT')
    result['TXT_count'] = len(txt_records)
    result['TXT_values'] = '|'.join([r.replace('"', '')[:200] for r in txt_records])[:1000]

    # SOA record
    soa_records = safe_dns_query(domain, 'SOA')
    if soa_records:
        result['SOA_value'] = soa_records[0][:300]

    # DMARC
    dmarc_records = safe_dns_query(f'_dmarc.{domain}', 'TXT')
    if dmarc_records:
        result['DMARC_present'] = 'Yes'
        result['DMARC_value'] = dmarc_records[0].replace('"', '')[:500]

    # IP geolocation
    ip_to_lookup = a_records[0] if a_records else original_ip
    if ip_to_lookup and not shutdown_flag:
        try:
            ip_info = get_ip_info(ip_to_lookup)
            result.update({
                'ip_asn': ip_info['asn'],
                'ip_org': ip_info['org'],
                'ip_country': ip_info['country'],
                'ip_region': ip_info['region'],
                'ip_city': ip_info['city'],
                'ip_latitude': str(ip_info['lat']),
                'ip_longitude': str(ip_info['lon'])
            })
        except:
            pass

    return result

def main():
    parser = argparse.ArgumentParser(description='Domain Analysis Script')
    parser.add_argument('--limit', type=int, help='Limit number of domains to process')
    parser.add_argument('--skip-whois', action='store_true', help='Skip WHOIS lookups (faster)')
    args = parser.parse_args()

    print("[*] Fetching domain list...")
    content = fetch_domains()

    if not content:
        print("[ERROR] Could not fetch domain list")
        return

    # Check if data changed
    if not check_if_changed(content):
        print("[*] Domain list unchanged. Skipping analysis.")
        return

    print("[*] Domain list changed. Starting analysis...")

    # Parse domains
    try:
        domains = json.loads(content)
    except:
        print("[ERROR] Failed to parse JSON")
        return

    # Apply limit if specified
    if args.limit:
        domains = domains[:args.limit]
        print(f"[*] Processing first {args.limit} domains")

    # Load progress
    progress = load_progress()
    processed_domains = set(progress.get("processed", []))

    # Filter already processed
    domains_to_process = [d for d in domains if d['domainname'] not in processed_domains]

    print(f"[*] Total domains: {len(domains)}")
    print(f"[*] Already processed: {len(processed_domains)}")
    print(f"[*] Remaining: {len(domains_to_process)}")
    print(f"[*] Workers: {MAX_WORKERS}, Rate limit: {RATE_LIMIT_DELAY}s")

    if len(domains_to_process) == 0:
        print("[*] All domains already processed!")
        return

    # Setup CSV
    csv_exists = Path(OUTPUT_FILE).exists()
    fieldnames = [
        'domain', 'registrarName', 'registrarIANAID', 'createdDate',
        'updatedDate', 'expiresDate', 'abuseEmail', 'nameServers', 'status',
        'registrant_name', 'registrant_organization', 'registrant_street1',
        'registrant_city', 'registrant_state', 'registrant_postalCode',
        'registrant_country', 'registrant_telephone', 'registrant_fax',
        'registrant_email', 'admin_name', 'admin_organization',
        'admin_street1', 'admin_city', 'admin_state', 'admin_postalCode',
        'admin_country', 'admin_telephone', 'admin_fax', 'admin_email',
        'tech_name', 'tech_organization', 'tech_street1', 'tech_city',
        'tech_state', 'tech_postalCode', 'tech_country', 'tech_telephone',
        'tech_fax', 'tech_email', 'A_count', 'A_values', 'AAAA_count',
        'AAAA_values', 'MX_count', 'MX_values', 'NS_count', 'NS_values',
        'TXT_count', 'TXT_values', 'SOA_value', 'DMARC_present',
        'DMARC_value', 'ip_asn', 'ip_org', 'ip_country', 'ip_region',
        'ip_city', 'ip_latitude', 'ip_longitude'
    ]

    # Process domains - write immediately, no memory holding
    completed = 0
    failed = 0
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit in smaller batches to avoid memory buildup
            batch_size = 100

            for i in range(0, len(domains_to_process), batch_size):
                if shutdown_flag:
                    break

                batch = domains_to_process[i:i+batch_size]
                futures = {
                    executor.submit(process_domain, domain): domain
                    for domain in batch
                }

                for future in as_completed(futures):
                    if shutdown_flag:
                        print("\n[!] Shutting down gracefully...")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    domain = futures[future]
                    try:
                        result = future.result(timeout=30)
                        if result:
                            # Write immediately to file
                            with write_lock:
                                with open(OUTPUT_FILE, 'a', newline='', encoding='utf-8') as csvfile:
                                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                                    if completed == 0 and not csv_exists:
                                        writer.writeheader()
                                    writer.writerow(result)
                                    # Immediate flush to disk
                                    csvfile.flush()
                                    import os
                                    os.fsync(csvfile.fileno())

                                processed_domains.add(domain['domainname'])
                                completed += 1

                                # Periodic progress save and stats
                                if completed % 10 == 0:  # More frequent saves
                                    progress["processed"] = processed_domains
                                    save_progress(progress)

                                if completed % BATCH_SAVE_SIZE == 0:
                                    elapsed = time.time() - start_time
                                    rate = completed / elapsed if elapsed > 0 else 0
                                    remaining = len(domains_to_process) - completed
                                    eta = remaining / rate if rate > 0 else 0

                                    print(f"[*] Progress: {completed}/{len(domains_to_process)} "
                                          f"({completed*100//len(domains_to_process)}%) | "
                                          f"Rate: {rate:.2f}/s | "
                                          f"ETA: {eta/3600:.1f}h | "
                                          f"Failed: {failed}")
                        else:
                            failed += 1

                    except Exception as e:
                        failed += 1
                        if failed % 100 == 0:
                            print(f"[WARN] {failed} failures so far")
                    finally:
                        # Clear result from memory immediately
                        result = None
                        del result

                # Clear batch futures from memory
                futures.clear()
                del futures

    finally:
        progress["processed"] = processed_domains
        save_progress(progress)

    elapsed = time.time() - start_time
    print(f"\n[*] Analysis complete!")
    print(f"[*] Processed: {completed} domains")
    print(f"[*] Failed: {failed} domains")
    print(f"[*] Time: {elapsed/3600:.2f} hours")
    print(f"[*] Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
