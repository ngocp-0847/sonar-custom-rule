#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
import sys
from typing import List, Dict, Tuple

from detector_base import VulnerabilityDetector

class PHPMassAssignmentDetector(VulnerabilityDetector):
    def __init__(self, path='.', recursive=False, verbose=False, exclude=None):
        super().__init__(path, recursive, verbose, exclude)
        
        # Các mẫu cần tìm kiếm
        self.patterns = {
            # Pattern cho hàm extract() với dữ liệu người dùng
            'extract': re.compile(r'extract\s*\(\s*\$_(POST|GET|REQUEST|FILES)', re.IGNORECASE),
            
            # Pattern cho việc gán trực tiếp từ $_POST/$_GET/$_REQUEST
            'direct_assignment': re.compile(r'\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*(?:\[[\'"a-zA-Z0-9_\s]+[\'"]?\])?\s*=\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),
            
            # Mass assignment với update/create trong các framework phổ biến
            'laravel_create': re.compile(r'::create\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),
            'laravel_update': re.compile(r'->update\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),
            'laravel_fill': re.compile(r'->fill\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),
            
            # CodeIgniter và các framework khác
            'codeigniter_insert': re.compile(r'->insert\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),
            'codeigniter_update': re.compile(r'->update\s*\(\s*[^,]+,\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),
            
            # Symfony
            'symfony_bind': re.compile(r'->bind(Request|Parameters)\s*\(\s*\$', re.IGNORECASE),
            
            # CakePHP
            'cakephp_save': re.compile(r'->save\s*\(\s*\$this->request->data', re.IGNORECASE),
            
            # Gán mảng từ người dùng
            'array_merge': re.compile(r'array_merge\s*\([^)]*\$_(POST|GET|REQUEST)[^)]*\)', re.IGNORECASE),
        }
    
    def should_scan_file(self, file_path: str) -> bool:
        """Determine if a file should be scanned based on its extension"""
        return file_path.endswith('.php')
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """Quét một file PHP để tìm lỗi mass assignment"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for i, line in enumerate(lines):
                    for pattern_name, pattern in self.patterns.items():
                        matches = pattern.finditer(line)
                        for match in matches:
                            vulnerabilities.append({
                                'file': file_path,
                                'line': i + 1,
                                'pattern': pattern_name,
                                'code': line.strip(),
                                'match': match.group(0),
                                'message': self._get_pattern_description(pattern_name)
                            })
        except Exception as e:
            if self.verbose:
                print(f"Lỗi khi quét file {file_path}: {e}")
        
        return vulnerabilities
    
    def _get_pattern_description(self, pattern_name: str) -> str:
        """Trả về mô tả dựa trên pattern đã phát hiện"""
        descriptions = {
            'extract': 'Lỗi extract() với dữ liệu người dùng',
            'direct_assignment': 'Gán trực tiếp từ dữ liệu người dùng',
            'laravel_create': 'Laravel mass assignment (create)',
            'laravel_update': 'Laravel mass assignment (update)',
            'laravel_fill': 'Laravel mass assignment (fill)',
            'codeigniter_insert': 'CodeIgniter mass assignment (insert)',
            'codeigniter_update': 'CodeIgniter mass assignment (update)',
            'symfony_bind': 'Symfony mass binding',
            'cakephp_save': 'CakePHP mass assignment (save)',
            'array_merge': 'Array merge với dữ liệu người dùng'
        }
        return descriptions.get(pattern_name, pattern_name)
    
    def scan(self) -> List[Dict]:
        """Override the base scan method to provide more specific output"""
        issues = super().scan()
        
        if self.verbose and issues:
            # Hiển thị phân loại lỗi
            pattern_counts = {}
            for issue in issues:
                pattern = issue['pattern']
                if pattern in pattern_counts:
                    pattern_counts[pattern] += 1
                else:
                    pattern_counts[pattern] = 1
            
            print("\n> Phân loại lỗi:")
            for pattern, count in pattern_counts.items():
                desc = self._get_pattern_description(pattern)
                print(f"   {desc}: {count} lỗi")
            
            print("\n> Khuyến nghị khắc phục:")
            print("   1. Sử dụng danh sách cho phép (allowlist) cho các trường cần cập nhật")
            print("   2. Tạo các DTO (Data Transfer Objects) riêng cho từng API")
            print("   3. Kiểm tra nghiêm ngặt dữ liệu đầu vào trước khi lưu/cập nhật")
            print("   4. Giới hạn và bảo vệ các trường nhạy cảm (is_admin, role, v.v.)")
            print("   5. Tránh sử dụng hàm extract() với dữ liệu không đáng tin cậy")
        
        return issues

def main():
    parser = argparse.ArgumentParser(description='Công cụ phát hiện lỗi Mass Parameter Assignment trong mã PHP')
    parser.add_argument('-d', '--path', default='.', help='Thư mục chứa mã PHP cần quét (mặc định: thư mục hiện tại)')
    parser.add_argument('-r', '--recursive', action='store_true', help='Quét đệ quy tất cả các thư mục con')
    parser.add_argument('-v', '--verbose', action='store_true', help='Hiển thị thông tin chi tiết về các lỗi')
    parser.add_argument('-o', '--output', help='Xuất kết quả ra file')
    parser.add_argument('-e', '--exclude', nargs='+', default=[], help='Các thư mục loại trừ')
    args = parser.parse_args()
    
    # Kiểm tra thư mục tồn tại
    if not os.path.exists(args.path):
        print(f"Lỗi: Path '{args.path}' không tồn tại")
        sys.exit(1)
    
    scanner = PHPMassAssignmentDetector(
        path=args.path,
        recursive=args.recursive,
        verbose=args.verbose,
        exclude=args.exclude
    )
    
    issues = scanner.scan()
    
    # Tạo báo cáo
    report = scanner.generate_report()
    
    # In hoặc lưu báo cáo
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"Đã xuất báo cáo ra file: {args.output}")
        except Exception as e:
            print(f"Lỗi khi xuất báo cáo: {e}")
            print(report)
    else:
        print(report)
    
if __name__ == '__main__':
    main()