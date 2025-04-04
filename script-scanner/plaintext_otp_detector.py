#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
from typing import List, Dict, Any

from detector_base import VulnerabilityDetector

class PlaintextOTPDetector(VulnerabilityDetector):
    """Phát hiện việc lưu trữ OTP dạng plaintext trong code"""
    
    def __init__(self, path='.', recursive=True, verbose=False, exclude=None):
        super().__init__(path, recursive, verbose, exclude)
        
        # Đăng ký các loại file detector
        self.file_detectors = {
            '.js': self._scan_js_file,
            '.ts': self._scan_ts_file,
            '.tsx': self._scan_ts_file,
            '.jsx': self._scan_js_file,
            '.php': self._scan_php_file
        }
        
        # Khởi tạo các patterns
        self._init_patterns()
    
    def _init_patterns(self):
        """Khởi tạo các pattern cho các ngôn ngữ khác nhau"""
        # JavaScript patterns
        self.js_patterns = [
            re.compile(r'\botp\s*[=:]\s*.*\bcreate\b', re.IGNORECASE),
            re.compile(r'\.create\(\s*\{.*\botp\b.*\}', re.IGNORECASE),
            re.compile(r'\.save\(\s*\{.*\botp\b.*\}', re.IGNORECASE),
            re.compile(r'\.insert\(\s*\{.*\botp\b.*\}', re.IGNORECASE),
            re.compile(r'localStorage\.(set|get)Item\(\s*[\'"].*otp.*[\'"]\s*,', re.IGNORECASE),
            re.compile(r'sessionStorage\.(set|get)Item\(\s*[\'"].*otp.*[\'"]\s*,', re.IGNORECASE),
            re.compile(r'document\.cookie\s*=.*otp', re.IGNORECASE),
            re.compile(r'console\.(log|info|warn|error)\(.*otp', re.IGNORECASE),
            re.compile(r'window\.location.*[\?&]otp=', re.IGNORECASE),
            re.compile(r'URLSearchParams.*otp', re.IGNORECASE)
        ]
        
        # TypeScript patterns
        self.ts_patterns = [
            re.compile(r'\botp\s*:\s*string.*[=:]\s*.*\bcreate\b', re.IGNORECASE),
            re.compile(r'\.create\(\s*\{.*\botp\b.*\}', re.IGNORECASE),
            re.compile(r'\.save\(\s*\{.*\botp\b.*\}', re.IGNORECASE),
            re.compile(r'interface.*\{\s*.*\botp\b\s*:\s*string', re.IGNORECASE),
            re.compile(r'type.*\{\s*.*\botp\b\s*:\s*string', re.IGNORECASE),
            re.compile(r'const\s*\[\s*otp\s*,\s*setOtp\s*\]\s*=\s*useState', re.IGNORECASE),
            re.compile(r'useSelector\(\s*state\s*=>\s*state\..*otp', re.IGNORECASE),
            re.compile(r'dispatch\(\s*.*otp.*\)', re.IGNORECASE),
            re.compile(r'\.data\s*\.\s*otp', re.IGNORECASE),
            re.compile(r'<.*\s+otp\s*=', re.IGNORECASE),
            re.compile(r'useContext\(.*\)\.otp', re.IGNORECASE)
        ]
        
        # PHP patterns
        self.php_patterns = [
            re.compile(r'\$otp\s*=.*insert\s+into', re.IGNORECASE),
            re.compile(r'INSERT\s+INTO.*\(\s*.*\botp\b.*\)', re.IGNORECASE),
            re.compile(r'UPDATE\s+.*SET\s+.*\botp\b\s*=', re.IGNORECASE),
            re.compile(r'\$stmt->execute\(\s*array\(.*\$otp.*\)\s*\)', re.IGNORECASE),
            re.compile(r'->save\(\s*\[.*\'otp\'.*\]', re.IGNORECASE),
            re.compile(r'\$_SESSION\[.*[\'"]otp[\'"]\]', re.IGNORECASE),
            re.compile(r'setcookie\(.*[\'"]otp[\'"]\s*,', re.IGNORECASE),
            re.compile(r'error_log\(.*\$otp', re.IGNORECASE),
            re.compile(r'file_put_contents\(.*\$otp', re.IGNORECASE),
            re.compile(r'\$cache->set\(.*\$otp', re.IGNORECASE),
            re.compile(r'echo.*\$otp', re.IGNORECASE),
            re.compile(r'var_dump\(.*\$otp', re.IGNORECASE)
        ]
    
    def should_scan_file(self, file_path: str) -> bool:
        """Determine if a file should be scanned based on its extension"""
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in self.file_detectors
    
    def _scan_js_file(self, file_path: str, content: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Scan JavaScript file for plaintext OTP"""
        issues = []
        
        for i, line in enumerate(lines):
            for pattern in self.js_patterns:
                if pattern.search(line):
                    issues.append({
                        'file': file_path,
                        'line': i + 1,
                        'code': line.strip(),
                        'issue_type': 'plaintext_otp_js',
                        'message': 'Lưu trữ OTP dạng plaintext trong JavaScript'
                    })
                    break
        
        return issues
    
    def _scan_ts_file(self, file_path: str, content: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Scan TypeScript file for plaintext OTP"""
        issues = []
        
        for i, line in enumerate(lines):
            for pattern in self.ts_patterns:
                if pattern.search(line):
                    issues.append({
                        'file': file_path,
                        'line': i + 1,
                        'code': line.strip(),
                        'issue_type': 'plaintext_otp_ts',
                        'message': 'Lưu trữ OTP dạng plaintext trong TypeScript'
                    })
                    break
        
        return issues
    
    def _scan_php_file(self, file_path: str, content: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Scan PHP file for plaintext OTP"""
        issues = []
        
        for i, line in enumerate(lines):
            for pattern in self.php_patterns:
                if pattern.search(line):
                    issues.append({
                        'file': file_path,
                        'line': i + 1,
                        'code': line.strip(),
                        'issue_type': 'plaintext_otp_php',
                        'message': 'Lưu trữ OTP dạng plaintext trong PHP'
                    })
                    break
        
        return issues
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file for plaintext OTP vulnerabilities"""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext not in self.file_detectors:
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Call the appropriate detector based on file extension
                return self.file_detectors[file_ext](file_path, content, lines)
        except Exception as e:
            if self.verbose:
                print(f"Lỗi khi quét file {file_path}: {str(e)}")
            return []

def main():
    parser = argparse.ArgumentParser(description='Phát hiện lỗi lưu trữ OTP dạng plaintext trong các file mã nguồn.')
    parser.add_argument('--path', '-p', type=str, default='.', help='Đường dẫn tới thư mục chứa mã nguồn cần quét.')
    parser.add_argument('--recursive', '-r', action='store_true', help='Quét đệ quy các thư mục con')
    parser.add_argument('--verbose', '-v', action='store_true', help='Hiển thị thông tin chi tiết')
    parser.add_argument('--output', '-o', type=str, help='Xuất báo cáo ra file')
    parser.add_argument('--exclude', '-e', nargs='+', default=[], help='Các thư mục loại trừ')
    parser.add_argument('--js', action='store_true', help='Chỉ quét các file JavaScript')
    parser.add_argument('--ts', action='store_true', help='Chỉ quét các file TypeScript')
    parser.add_argument('--php', action='store_true', help='Chỉ quét các file PHP')
    args = parser.parse_args()
    
    detector = PlaintextOTPDetector(
        path=args.path,
        recursive=args.recursive,
        verbose=args.verbose,
        exclude=args.exclude
    )
    
    # Nếu có chỉ định loại file cụ thể, chỉ giữ lại detector cho loại đó
    if args.js or args.ts or args.php:
        allowed_extensions = []
        if args.js:
            allowed_extensions.extend(['.js', '.jsx'])
        if args.ts:
            allowed_extensions.extend(['.ts', '.tsx'])
        if args.php:
            allowed_extensions.append('.php')
        
        # Lọc ra các detectors được chỉ định
        detector.file_detectors = {ext: func for ext, func in detector.file_detectors.items() 
                                if ext in allowed_extensions}
    
    issues = detector.scan()
    
    if issues:
        print(f"\nTìm thấy {len(issues)} lỗi tiềm ẩn về lưu trữ OTP dạng plaintext:")
        for i, issue in enumerate(issues, 1):
            print(f"\n{i}. File: {issue['file']} (line {issue['line']})")
            print(f"   Mô tả: {issue['message']}")
            print(f"   Code: {issue['code']}")
        
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    for issue in issues:
                        f.write(f"File: {issue['file']} (line {issue['line']})\n")
                        f.write(f"Mô tả: {issue['message']}\n")
                        f.write(f"Code: {issue['code']}\n\n")
                print(f"\nĐã xuất báo cáo ra file: {args.output}")
            except Exception as e:
                print(f"Lỗi khi xuất báo cáo: {str(e)}")
    else:
        print("Không tìm thấy lỗi lưu trữ OTP dạng plaintext nào.")

if __name__ == '__main__':
    main()
