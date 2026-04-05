#!/usr/bin/env python3
import argparse
import yaml
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import sys

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from utils.parser import parse_db_url
from utils.html_report import generate_html_report, save_report
from scanners.redis_scanner import RedisScanner
from scanners.mysql_scanner import MySQLScanner
from scanners.postgresql_scanner import PostgreSQLScanner
from scanners.mongodb_scanner import MongoDBScanner

def load_config(config_path):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def load_targets(file_path):
    targets = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    target = parse_db_url(line)
                    targets.append(target)
                except ValueError as e:
                    print(f"Warning: Skipping invalid URL '{line}': {e}")
    return targets

def get_scanner(db_type, config):
    scanners = {
        'redis': RedisScanner,
        'mysql': MySQLScanner,
        'postgresql': PostgreSQLScanner,
        'mongodb': MongoDBScanner
    }
    scanner_class = scanners.get(db_type)
    if scanner_class:
        return scanner_class(config)
    else:
        raise ValueError(f"No scanner available for {db_type}")

def scan_target(target, config):
    db_type = target['type']
    scanner = get_scanner(db_type, config)
    return scanner.scan(target)

def main():
    parser = argparse.ArgumentParser(description='Database Vulnerability Scanner')
    parser.add_argument('-f', '--file', required=True, help='Input file with database URLs')
    parser.add_argument('-o', '--output', default='report.html', help='Output HTML report file')
    parser.add_argument('-c', '--config', default='config/config.yaml', help='Configuration file')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads (overrides config)')

    args = parser.parse_args()

    # Load configuration
    config_path = os.path.join(os.path.dirname(__file__), '..', args.config)
    config = load_config(config_path)

    if args.threads:
        config['scanner']['threads'] = args.threads

    # Load targets
    targets = load_targets(args.file)
    if not targets:
        print("No valid targets found in input file.")
        return

    print(f"Loaded {len(targets)} targets. Starting scan with {config['scanner']['threads']} threads...")

    # Scan targets
    vulnerabilities = []
    with ThreadPoolExecutor(max_workers=config['scanner']['threads']) as executor:
        futures = [executor.submit(scan_target, target, config['scanner']) for target in targets]
        for future in as_completed(futures):
            try:
                result = future.result()
                vulnerabilities.extend(result)
            except Exception as e:
                print(f"Error scanning target: {e}")

    # Generate report
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_html = generate_html_report(vulnerabilities, len(targets), timestamp)

    # Save report
    output_path = args.output
    save_report(report_html, output_path)
    print(f"Scan completed. Report saved to {output_path}")
    print(f"Found {len(vulnerabilities)} vulnerabilities.")

if __name__ == '__main__':
    main()