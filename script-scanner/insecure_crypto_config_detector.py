#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
from typing import List, Dict, Any
from detector_base import VulnerabilityDetector

class InsecureCryptoConfigDetector(VulnerabilityDetector):
    """Detector for insecure cryptographic configurations including IVs, cipher modes, and other settings."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.detector_name = "insecure-crypto-config"
        
        # Define insecure configurations to detect
        self.insecure_block_modes = [
            r'ECB',  # Electronic Code Book mode
            r'\.setCipherMode\s*\(\s*["\']?ECB["\']?\s*\)',
            r'createEncryptor\s*\([^,]+,[^,]+,\s*["\']?ECB["\']?\s*\)',
            r'CipherMode\.ECB',
            r'AES/ECB/',
            r'Cipher\.getInstance\s*\(\s*["\'].*ECB.*["\']'
        ]
        
        self.insecure_iv_patterns = [
            r'setIV\s*\(\s*["\'][a-zA-Z0-9_]+["\']',  # Hardcoded IV
            r'new\s+IV\s*\(\s*["\'][a-zA-Z0-9_]+["\']',
            r'InitializationVector\s*\(\s*new\s+byte\[\]\s*{[^}]+}\s*\)',  # Hardcoded IV in byte array
            r'iv\s*=\s*b?["\'][a-zA-Z0-9_]+["\']',
            r'IvParameterSpec\s*\(\s*[^)]*"[^"]+"\s*\)',
            r'IvParameterSpec\s*\(\s*new\s+byte\[\]\s*\{\s*0,\s*0',  # Zero or predictable IV
            r'new\s+byte\[16\];',  # Potential uninitialized IV
        ]
        
        self.insecure_padding_patterns = [
            r'NoPadding',
            r'PKCS1Padding',  # Vulnerable to padding oracle attacks
            r'\.setPaddingMode\s*\(\s*["\']?NoPadding["\']?\s*\)',
            r'Cipher\.getInstance\s*\(\s*["\'].*NoPadding.*["\']',
            r'Cipher\.getInstance\s*\(\s*["\'].*PKCS1Padding.*["\']'
        ]
        
    def should_scan_file(self, file_path: str) -> bool:
        """Determine if the file should be scanned based on extension"""
        extensions = ['.py', '.php', '.js', '.java', '.cs', '.go', '.rb', '.c', '.cpp', '.h', '.swift', '.kt', '.ts']
        _, ext = os.path.splitext(file_path.lower())
        return ext in extensions

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file for insecure cryptographic configurations"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Check for insecure block modes (e.g., ECB)
                for pattern in self.insecure_block_modes:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            issues.append({
                                'file': file_path,
                                'line': i + 1,
                                'message': 'Insecure block mode detected (likely ECB). ECB mode does not provide sufficient data confidentiality.',
                                'code': line.strip(),
                                'detector': self.detector_name
                            })
                
                # Check for insecure IV configurations
                for pattern in self.insecure_iv_patterns:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            issues.append({
                                'file': file_path,
                                'line': i + 1,
                                'message': 'Potentially insecure Initialization Vector (IV) detected. IVs should be random and unique for each encryption.',
                                'code': line.strip(),
                                'detector': self.detector_name
                            })
                
                # Check for insecure padding methods
                for pattern in self.insecure_padding_patterns:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            issues.append({
                                'file': file_path,
                                'line': i + 1,
                                'message': 'Insecure padding method detected. This may be vulnerable to padding oracle attacks.',
                                'code': line.strip(),
                                'detector': self.detector_name
                            })
                            
                # Detect IV reuse patterns
                iv_reuse_pattern = r'(?:for|while).+\{.*AES.*\}'
                if re.search(iv_reuse_pattern, content, re.DOTALL | re.IGNORECASE):
                    # Find the approximate line
                    for i, line in enumerate(lines):
                        if re.search(r'(?:for|while)', line, re.IGNORECASE):
                            if any(re.search(r'IV|InitializationVector|cipher\.init', l, re.IGNORECASE) for l in lines[i:i+10]):
                                issues.append({
                                    'file': file_path,
                                    'line': i + 1,
                                    'message': 'Potential IV reuse detected in loop. Each encryption operation should use a unique IV.',
                                    'code': line.strip(),
                                    'detector': self.detector_name
                                })
                                break

        except Exception as e:
            if self.verbose:
                print(f"Error scanning {file_path}: {str(e)}")
        
        return issues
