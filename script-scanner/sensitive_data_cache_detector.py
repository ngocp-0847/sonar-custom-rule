#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
import json
from typing import List, Dict, Any

from detector_base import VulnerabilityDetector

class SensitiveDataCacheDetector(VulnerabilityDetector):
    def __init__(self, path='.', recursive=True, verbose=False, exclude=None):
        super().__init__(path, recursive, verbose, exclude)
        
        if exclude is None:
            self.exclude = ['.git', 'node_modules', 'vendor', 'dist', 'build']
        
        # Định nghĩa các pattern cho dữ liệu nhạy cảm
        self.sensitive_data_patterns = [
            r"password", r"passwd", r"secret", r"credential",
            r"credit.?card", r"card.?number", r"ssn", r"social.?security",
            r"auth.?token", r"api.?key", r"private.?key", r"key.?secret",
            r"account.?number", r"banking", r"personal.?id", r"birthdate",
            r"address", r"phone.?number", r"email"
        ]
        
        # Pattern cho các vấn đề cache
        self.java_spring_patterns = {
            "missing_cache_control": r"@GetMapping|@PostMapping|@RequestMapping.*\s+public\s+ResponseEntity.*\s+\{(?!.*Cache-Control)",
            "sensitive_response": r"return\s+ResponseEntity\.ok\(.*\)"
        }
        
        self.nodejs_patterns = {
            "redis_cache_set": r"(?:redisClient|redis)\.set\([^)]*JSON\.stringify\([^)]*\)",
            "cache_store": r"cache\.set\(|cache\.put\(|localStorage\.|sessionStorage\.",
            "missing_expiry": r"\.set\([^)]*\)(?!.*expire)"
        }
        
        self.php_patterns = {
            "cache_store": r"Cache::put|cache\([^)]*\)|->cache\(",
            "session_data": r"\$_SESSION\[.*\]\s*=",
        }
        
        self.headers_patterns = {
            "missing_cache_headers": r"(?:response|res)\.(?:set|header)\([^)]*\)(?!.*(?:Cache-Control|no-cache|no-store|must-revalidate))",
        }

    def should_scan_file(self, file_path: str) -> bool:
        """Determine if a file should be scanned based on its extension"""
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in ['.java', '.kt', '.js', '.ts', '.jsx', '.tsx', '.php', '.py', '.rb', '.cs']

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Quét một file để tìm các vấn đề tiềm ẩn về lưu trữ dữ liệu nhạy cảm trong cache"""
        issues = []
        
        # Xác định loại file
        file_ext = os.path.splitext(file_path)[1].lower()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                line_number = 1
                
                for line in content.split('\n'):
                    # Kiểm tra dữ liệu nhạy cảm
                    sensitive_data_found = False
                    for pattern in self.sensitive_data_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            sensitive_data_found = True
                            break
                    
                    # Nếu tìm thấy dữ liệu nhạy cảm, kiểm tra các vấn đề cache
                    if sensitive_data_found:
                        # Kiểm tra code Java
                        if file_ext in ['.java', '.kt']:
                            for issue_type, pattern in self.java_spring_patterns.items():
                                if re.search(pattern, line, re.IGNORECASE):
                                    issues.append({
                                        'file': file_path,
                                        'line': line_number,
                                        'code': line.strip(),
                                        'issue_type': issue_type,
                                        'message': f'Dữ liệu nhạy cảm có thể được lưu trong cache (thiếu header cache-control)'
                                    })
                        
                        # Kiểm tra code JavaScript/Node.js
                        elif file_ext in ['.js', '.ts', '.jsx', '.tsx']:
                            for issue_type, pattern in self.nodejs_patterns.items():
                                if re.search(pattern, line, re.IGNORECASE):
                                    issues.append({
                                        'file': file_path,
                                        'line': line_number,
                                        'code': line.strip(),
                                        'issue_type': issue_type,
                                        'message': f'Dữ liệu nhạy cảm có thể được lưu trong cache'
                                    })
                        
                        # Kiểm tra code PHP
                        elif file_ext in ['.php']:
                            for issue_type, pattern in self.php_patterns.items():
                                if re.search(pattern, line, re.IGNORECASE):
                                    issues.append({
                                        'file': file_path,
                                        'line': line_number,
                                        'code': line.strip(),
                                        'issue_type': issue_type,
                                        'message': f'Dữ liệu nhạy cảm có thể được lưu trong cache'
                                    })
                        
                        # Kiểm tra các header HTTP
                        for issue_type, pattern in self.headers_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                issues.append({
                                    'file': file_path,
                                    'line': line_number,
                                    'code': line.strip(),
                                    'issue_type': issue_type,
                                    'message': f'Thiếu header ngăn chặn cache cho dữ liệu nhạy cảm'
                                })
                    
                    line_number += 1
                
                # Kiểm tra các pattern ở mức file (phân tích ngữ cảnh rộng hơn)
                if file_ext in ['.java', '.kt']:
                    # Kiểm tra các controller không có header Cache-Control
                    if 'ResponseEntity' in content and '@RestController' in content:
                        if '@GetMapping' in content and 'Cache-Control' not in content:
                            issues.append({
                                'file': file_path,
                                'line': 0,
                                'code': '',
                                'issue_type': 'file_level_missing_cache_control',
                                'message': 'RestController trả về dữ liệu mà không có header Cache-Control'
                            })
                
                elif file_ext in ['.js', '.ts', '.jsx', '.tsx']:
                    # Kiểm tra lưu trữ session đầy đủ trong Redis
                    if 'redis' in content.lower() and 'session' in content.lower():
                        if re.search(r'JSON\.stringify\(.*user', content, re.IGNORECASE):
                            issues.append({
                                'file': file_path,
                                'line': 0,
                                'code': '',
                                'issue_type': 'file_level_redis_session_storage',
                                'message': 'Lưu trữ dữ liệu phiên người dùng đầy đủ trong Redis cache'
                            })
        
        except Exception as e:
            if self.verbose:
                print(f"Lỗi khi quét file {file_path}: {str(e)}")
        
        return issues

def main():
    parser = argparse.ArgumentParser(description='Công cụ quét lỗi lưu trữ dữ liệu nhạy cảm trong bộ nhớ cache')
    parser.add_argument('--path', '-p', default='.', help='Đường dẫn đến file hoặc thư mục cần quét')
    parser.add_argument('--recursive', '-r', action='store_true', help='Quét đệ quy các thư mục con')
    parser.add_argument('--verbose', '-v', action='store_true', help='Hiển thị thông tin chi tiết')
    parser.add_argument('--output', '-o', help='File đầu ra (định dạng JSON)')
    parser.add_argument('--exclude', '-e', nargs='+', 
                        default=['.git', 'node_modules', 'vendor', 'dist', 'build'],
                        help='Các thư mục cần loại trừ')
    args = parser.parse_args()
    
    scanner = SensitiveDataCacheDetector(
        path=args.path,
        recursive=args.recursive,
        verbose=args.verbose,
        exclude=args.exclude
    )
    
    issues = scanner.scan()
    
    if issues:
        print(f"\nTìm thấy {len(issues)} vấn đề tiềm ẩn về lưu trữ dữ liệu nhạy cảm trong cache:")
        for i, issue in enumerate(issues, 1):
            print(f"\n{i}. File: {issue['file']}")
            if issue['line'] > 0:
                print(f"   Dòng: {issue['line']}")
            print(f"   Loại lỗi: {issue['issue_type']}")
            print(f"   Mô tả: {issue['message']}")
            if issue['code']:
                print(f"   Đoạn code: {issue['code']}")
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(issues, f, ensure_ascii=False, indent=2)
            print(f"\nĐã lưu kết quả vào file {args.output}")
    else:
        print("Không tìm thấy vấn đề nào về lưu trữ dữ liệu nhạy cảm trong cache.")

if __name__ == "__main__":
    main()
