#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import sys
from typing import List, Dict, Any
import importlib

# Import detector classes
from detector_base import VulnerabilityDetector
from mass_assign_detector import PHPMassAssignmentDetector
from sensitive_data_cache_detector import SensitiveDataCacheDetector
from plaintext_otp_detector import PlaintextOTPDetector
from insecure_crypto_config_detector import InsecureCryptoConfigDetector

def get_available_detectors():
    """Returns a dictionary of available detectors"""
    return {
        'mass-assignment': {
            'class': PHPMassAssignmentDetector,
            'description': 'Detects mass assignment vulnerabilities in PHP code'
        },
        'sensitive-cache': {
            'class': SensitiveDataCacheDetector,
            'description': 'Detects sensitive data stored in cache'
        },
        'plaintext-otp': {
            'class': PlaintextOTPDetector,
            'description': 'Detects plaintext OTP storage in code'
        },
        'insecure-crypto-config': {
            'class': InsecureCryptoConfigDetector,
            'description': 'Detects insecure configurations of IVs, cipher modes, and crypto settings'
        },
    }

def main():
    # Get available detectors
    available_detectors = get_available_detectors()
    
    # Create parser
    parser = argparse.ArgumentParser(
        description='Security vulnerability scanner for code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Available detectors:\n' + '\n'.join(
            [f"  {key}: {value['description']}" for key, value in available_detectors.items()]
        )
    )
    
    # Add common arguments
    parser.add_argument('--path', '-p', default='.', 
                        help='Path to directory or file to scan (default: current directory)')
    parser.add_argument('--recursive', '-r', action='store_true',
                        help='Scan directories recursively')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed output')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--exclude', '-e', nargs='+', default=[],
                        help='Directories to exclude (e.g., node_modules, vendor)')
    
    # Add detector selection arguments
    detector_group = parser.add_argument_group('detectors')
    detector_group.add_argument('--all', action='store_true',
                              help='Run all available detectors')
    
    for key in available_detectors.keys():
        detector_group.add_argument(f'--{key}', action='store_true',
                                   help=f'Run the {key} detector')
    
    args = parser.parse_args()
    
    # Determine which detectors to run
    detectors_to_run = []
    if args.all:
        detectors_to_run = list(available_detectors.keys())
    else:
        for detector in available_detectors.keys():
            if getattr(args, detector.replace('-', '_')):
                detectors_to_run.append(detector)
    
    # If no detectors specified, run all
    if not detectors_to_run:
        detectors_to_run = list(available_detectors.keys())
        print("No specific detectors selected. Running all detectors.")
    
    # Configure common parameters
    scan_params = {
        'path': args.path,
        'recursive': args.recursive,
        'verbose': args.verbose,
        'exclude': args.exclude
    }
    
    all_issues = []
    
    # Run selected detectors
    for detector_key in detectors_to_run:
        detector_info = available_detectors[detector_key]
        detector_class = detector_info['class']
        
        print(f"\nRunning {detector_key} detector...")
        detector = detector_class(**scan_params)
        issues = detector.scan()
        
        if issues:
            all_issues.extend(issues)
            print(f"Found {len(issues)} potential issues.")
        else:
            print("No issues found.")
    
    # Generate combined report
    if all_issues:
        print(f"\nTotal issues found: {len(all_issues)}")
        
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    for issue in all_issues:
                        f.write(f"{issue['detector']}: {issue['file']}:{issue.get('line', 0)}\n")
                        f.write(f"  {issue['message']}\n")
                        if 'code' in issue and issue['code']:
                            f.write(f"  Code: {issue['code']}\n")
                        f.write("\n")
                print(f"Results written to {args.output}")
            except Exception as e:
                print(f"Error writing to output file: {str(e)}")
    else:
        print("\nNo security issues found!")

if __name__ == "__main__":
    main()
