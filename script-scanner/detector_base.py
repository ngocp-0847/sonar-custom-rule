#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from typing import List, Dict, Any, Optional

class VulnerabilityDetector:
    """Base class for all vulnerability detectors"""
    
    def __init__(self, path: str = '.', recursive: bool = False, 
                 verbose: bool = False, exclude: List[str] = None):
        """
        Initialize the detector
        
        Args:
            path: Directory or file path to scan
            recursive: Whether to scan directories recursively
            verbose: Whether to show detailed output
            exclude: List of directories to exclude from scanning
        """
        self.path = path
        self.recursive = recursive
        self.verbose = verbose
        self.exclude = exclude if exclude else []
        self.issues = []
        self.detector_name = self.__class__.__name__
    
    def should_scan_file(self, file_path: str) -> bool:
        """
        Determine if a file should be scanned based on its extension
        
        Override this in subclasses to implement specific file filtering
        """
        return True
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a single file for vulnerabilities
        
        Override this in subclasses to implement specific file scanning
        """
        return []
    
    def find_files(self) -> List[str]:
        """Find all files that should be scanned"""
        files_to_scan = []
        
        # If path is a file, scan only that file
        if os.path.isfile(self.path):
            if self.should_scan_file(self.path):
                files_to_scan.append(self.path)
            return files_to_scan
        
        # If path is a directory, find all files to scan
        if self.recursive:
            for root, dirs, files in os.walk(self.path):
                # Skip excluded directories
                dirs[:] = [d for d in dirs if d not in self.exclude]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.should_scan_file(file_path):
                        files_to_scan.append(file_path)
        else:
            # Non-recursive scan
            for item in os.listdir(self.path):
                file_path = os.path.join(self.path, item)
                if os.path.isfile(file_path) and self.should_scan_file(file_path):
                    files_to_scan.append(file_path)
        
        return files_to_scan
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for vulnerabilities
        
        Returns:
            List of detected issues
        """
        self.issues = []
        
        # Find files to scan
        files = self.find_files()
        
        if self.verbose:
            print(f"Found {len(files)} files to scan")
        
        # Scan each file
        for file_path in files:
            if self.verbose:
                print(f"Scanning {file_path}")
            
            try:
                file_issues = self.scan_file(file_path)
                
                # Add detector name to each issue
                for issue in file_issues:
                    if 'detector' not in issue:
                        issue['detector'] = self.detector_name
                
                self.issues.extend(file_issues)
            
            except Exception as e:
                if self.verbose:
                    print(f"Error scanning {file_path}: {str(e)}")
        
        return self.issues
    
    def generate_report(self) -> str:
        """Generate a report of detected issues"""
        if not self.issues:
            return f"No issues found by {self.detector_name}"
        
        report = f"Found {len(self.issues)} issues by {self.detector_name}:\n\n"
        
        for issue in self.issues:
            report += f"File: {issue['file']}"
            if 'line' in issue:
                report += f":{issue['line']}"
            report += f"\nIssue: {issue['message']}\n"
            
            if 'code' in issue and issue['code']:
                report += f"Code: {issue['code']}\n"
            
            report += "\n"
        
        return report
