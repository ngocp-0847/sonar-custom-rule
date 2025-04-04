#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
import json
from typing import List, Dict, Any, Tuple, Optional

from detector_base import VulnerabilityDetector

class ImproperDataRetentionDetector(VulnerabilityDetector):
    """
    Detector cho lỗi không phân loại và lưu trữ thông tin cá nhân nhạy cảm đúng cách
    """
    
    def __init__(self, path='.', recursive=True, verbose=False, exclude=None):
        super().__init__(path, recursive, verbose, exclude)
        
        if exclude is None:
            self.exclude = ['.git', 'node_modules', 'vendor', 'dist', 'build']
        
        # Định nghĩa các pattern dữ liệu nhạy cảm PII (Personally Identifiable Information)
        self.pii_patterns = [
            r"social.?security.?number",
            r"ssn",
            r"passport.?number",
            r"driver.?license",
            r"id.?card",
            r"date.?of.?birth",
            r"birth.?date", 
            r"credit.?card",
            r"card.?number",
            r"cvv",
            r"ccv",
            r"home.?address",
            r"billing.?address",
            r"medical.?(id|record)",
            r"health.?insurance",
            r"bank.?account",
            r"iban",
            r"password",
            r"credential",
            r"full.?name",
            r"personal.?id"
        ]
        
        # Pattern cho các mẫu lỗi lưu trữ phổ biến
        # 1. Các mô hình/entity lưu trữ không có chính sách xóa
        self.model_definition_patterns = {
            "ts_entity_no_retention": [
                # TypeScript: Class định nghĩa entity không có trường thời hạn lưu trữ
                r"(?:export\s+)?class\s+(\w+)(?:\s+extends\s+\w+)?(?:\s+implements\s+\w+(?:,\s*\w+)*)?\s*{(?![^}]*(?:expiresAt|retentionPeriod|scheduledDeletion|validUntil|expiryDate|retention))",
                # TypeScript: Interface định nghĩa dữ liệu không có trường thời hạn
                r"(?:export\s+)?interface\s+(\w+)(?:\s+extends\s+\w+(?:,\s*\w+)*)?\s*{(?![^}]*(?:expiresAt|retentionPeriod|scheduledDeletion|validUntil|expiryDate|retention))"
            ],
            "js_entity_no_retention": [
                # JavaScript: schema mongoose không có trường thời hạn
                r"(?:new\s+Schema|mongoose\.Schema)\(\s*{(?![^}]*(?:expiresAt|retentionPeriod|scheduledDeletion|validUntil|expiryDate|retention))", 
                # JavaScript: class định nghĩa model
                r"class\s+(\w+)(?:\s+extends\s+\w+)?(?:\s+implements\s+\w+(?:,\s*\w+)*)?\s*{(?![^}]*(?:expiresAt|retentionPeriod|scheduledDeletion|validUntil|expiryDate|retention))"
            ]
        }

        # 2. Lưu trữ dữ liệu không có thời hạn
        self.storage_without_expiry_patterns = {
            "ts_js_storage_no_expiry": [
                # TypeScript/JavaScript: Lưu trữ trong database không có thời hạn
                r"(?:create|insert|save|add|update)\w*\s*\(\s*(?:{[^}]*}|\w+)",
                # TypeScript/JavaScript: Lưu trữ trong cache/localStorage không có thời hạn  
                r"(?:cache|localStorage|sessionStorage)\.set\w*\s*\(\s*(?:[^,)]*,\s*[^,)]*)\s*\)(?![^;]*(?:expire|ttl|maxAge))",
                # TypeScript/JavaScript: Lưu trữ trong Redis không có thời hạn
                r"(?:redis|redisClient)\.set\w*\s*\(\s*(?:[^,)]*,\s*[^,)]*)\s*\)(?![^;]*(?:EX|PX|EXPIRE|ex:|px:|expire:|expiryMode))"
            ]
        }

        # 3. Không có cơ chế tự động xóa dữ liệu
        self.missing_auto_deletion_patterns = {
            "missing_cleanup_mechanism": [
                # Thiếu cơ chế tự động xóa dữ liệu cũ
                r"@cron|@scheduled|cron\.schedule|setInterval|setTimeout"
            ]
        }

        # 4. Lưu trữ log có thông tin nhạy cảm vô thời hạn
        self.log_sensitive_data_patterns = {
            "logging_sensitive_data": [
                # TypeScript/JavaScript: Ghi log thông tin nhạy cảm
                r"(?:console|logger)\.(?:log|info|debug|warn|error)\s*\([^)]*(?:user|account|customer)",
                # TypeScript/JavaScript: Configuration logging không có rotation
                r"(?:winston|bunyan|log4js|pino).createLogger\s*\([^)]*\)(?![^;]*rotation)"
            ]
        }

        # 5. Không phân loại dữ liệu theo mức độ nhạy cảm
        self.missing_data_classification_patterns = {
            "missing_data_classification": [
                # TypeScript/JavaScript: Định nghĩa dữ liệu không có annotation phân loại
                r"(?:@Entity|@Table)\s*\(\s*{[^}]*}\s*\)(?![^{]*@DataClassification)",
                # TypeScript: Không có annotation/decorator cho việc phân loại dữ liệu
                r"@(?:Column|Field|Property)\s*\(\s*{[^}]*}\s*\)(?![^{]*(?:classification|sensitivity|retention))"
            ]
        }
    
    def should_scan_file(self, file_path: str) -> bool:
        """Xác định xem file có nên được quét hay không dựa trên phần mở rộng"""
        file_ext = os.path.splitext(file_path)[1].lower()
        # Ưu tiên quét các file TypeScript/JavaScript
        return file_ext in ['.ts', '.tsx', '.js', '.jsx', '.java', '.php', '.py', '.cs', '.rb', '.sql']
    
    def get_code_context(self, content: str, line_index: int, context_lines: int = 3) -> str:
        """Lấy ngữ cảnh của đoạn code xung quanh dòng được chỉ định"""
        lines = content.split('\n')
        start = max(0, line_index - context_lines)
        end = min(len(lines), line_index + context_lines + 1)
        
        context = []
        for i in range(start, end):
            prefix = ">" if i == line_index else " "
            context.append(f"{prefix} {lines[i]}")
        
        return '\n'.join(context)
    
    def check_for_pii(self, line: str) -> bool:
        """Kiểm tra dòng có chứa dữ liệu PII hay không"""
        for pattern in self.pii_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False
    
    def check_for_patterns(self, content: str, line: str, line_number: int, 
                           pattern_groups: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Kiểm tra các mẫu lỗi trong dòng code"""
        issues = []
        
        for issue_type, patterns in pattern_groups.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Lấy thêm context để quyết định chính xác hơn
                    has_pii = self.check_for_pii(line)
                    
                    # Nếu không thấy PII trong dòng hiện tại, kiểm tra thêm 10 dòng tiếp theo
                    if not has_pii:
                        # Tìm kiếm PII trong 10 dòng tiếp theo
                        lines = content.split('\n')
                        for i in range(line_number, min(line_number + 10, len(lines))):
                            if self.check_for_pii(lines[i]):
                                has_pii = True
                                break
                    
                    if has_pii:
                        # Dựa vào issue_type để mô tả vấn đề cụ thể
                        message = self.get_issue_message(issue_type)
                        
                        issues.append({
                            'file': '',  # Sẽ được cập nhật trong scan_file
                            'line': line_number,
                            'code': line.strip(),
                            'context': self.get_code_context(content, line_number - 1),
                            'issue_type': issue_type,
                            'message': message
                        })
        
        return issues
    
    def get_issue_message(self, issue_type: str) -> str:
        """Trả về message mô tả chi tiết cho từng loại vấn đề"""
        messages = {
            "ts_entity_no_retention": "Entity/Model chứa thông tin cá nhân nhạy cảm (PII) nhưng không có cơ chế quản lý thời hạn lưu trữ",
            "js_entity_no_retention": "Model chứa thông tin cá nhân nhạy cảm (PII) nhưng không có cơ chế quản lý thời hạn lưu trữ",
            "ts_js_storage_no_expiry": "Lưu trữ thông tin cá nhân nhạy cảm (PII) mà không thiết lập thời gian hết hạn",
            "missing_cleanup_mechanism": "Có thể chứa dữ liệu nhạy cảm nhưng không tìm thấy cơ chế tự động xóa dữ liệu cũ",
            "logging_sensitive_data": "Có thể ghi log thông tin nhạy cảm mà không có cơ chế xoay vòng hoặc xóa tự động",
            "missing_data_classification": "Không phân loại dữ liệu cá nhân nhạy cảm theo mức độ bảo mật và thời hạn lưu trữ"
        }
        
        return messages.get(issue_type, "Lỗi tiềm ẩn trong việc lưu trữ thông tin cá nhân nhạy cảm")
    
    def analyze_file_content(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Phân tích nội dung file để tìm kiếm lỗi"""
        issues = []
        has_pii_data = False
        has_automatic_cleanup = False
        
        # First pass: check if the file has PII data
        for pattern in self.pii_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                has_pii_data = True
                break
        
        # If no PII data found, skip further analysis
        if not has_pii_data:
            return issues
        
        # Check for automatic cleanup mechanisms in the entire file
        for pattern in self.missing_auto_deletion_patterns["missing_cleanup_mechanism"]:
            if re.search(pattern, content, re.IGNORECASE):
                has_automatic_cleanup = True
                break
        
        # Process line by line to find specific issues
        lines = content.split('\n')
        for line_number, line in enumerate(lines, 1):
            # Check different pattern groups
            entity_issues = self.check_for_patterns(content, line, line_number, self.model_definition_patterns)
            storage_issues = self.check_for_patterns(content, line, line_number, self.storage_without_expiry_patterns)
            log_issues = self.check_for_patterns(content, line, line_number, self.log_sensitive_data_patterns)
            classification_issues = self.check_for_patterns(content, line, line_number, self.missing_data_classification_patterns)
            
            # Combine issues
            for issue in entity_issues + storage_issues + log_issues + classification_issues:
                issue['file'] = file_path
                issues.append(issue)
        
        # Add file-level issue if PII data exists but no automatic cleanup mechanism
        if has_pii_data and not has_automatic_cleanup:
            issues.append({
                'file': file_path,
                'line': 0,
                'code': '',
                'issue_type': 'missing_cleanup_mechanism',
                'message': 'File chứa dữ liệu nhạy cảm nhưng không tìm thấy cơ chế tự động xóa dữ liệu cũ'
            })
        
        return issues
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Quét một file để tìm các vấn đề về lưu trữ thông tin cá nhân nhạy cảm"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                issues = self.analyze_file_content(file_path, content)
                return issues
                
        except Exception as e:
            if self.verbose:
                print(f"Lỗi khi quét file {file_path}: {str(e)}")
            return []

def main():
    parser = argparse.ArgumentParser(description='Công cụ quét lỗi không phân loại và lưu trữ thông tin cá nhân nhạy cảm đúng cách')
    parser.add_argument('--path', '-p', default='.', help='Đường dẫn đến file hoặc thư mục cần quét')
    parser.add_argument('--recursive', '-r', action='store_true', help='Quét đệ quy các thư mục con')
    parser.add_argument('--verbose', '-v', action='store_true', help='Hiển thị thông tin chi tiết')
    parser.add_argument('--output', '-o', help='File đầu ra (định dạng JSON)')
    parser.add_argument('--exclude', '-e', nargs='+', 
                        default=['.git', 'node_modules', 'vendor', 'dist', 'build'],
                        help='Các thư mục cần loại trừ')
    args = parser.parse_args()
    
    scanner = ImproperDataRetentionDetector(
        path=args.path,
        recursive=args.recursive,
        verbose=args.verbose,
        exclude=args.exclude
    )
    
    issues = scanner.scan()
    
    if issues:
        print(f"\nTìm thấy {len(issues)} vấn đề tiềm ẩn về việc lưu trữ thông tin cá nhân nhạy cảm không đúng cách:")
        for i, issue in enumerate(issues, 1):
            print(f"\n{i}. File: {issue['file']}")
            if issue['line'] > 0:
                print(f"   Dòng: {issue['line']}")
            print(f"   Loại lỗi: {issue['issue_type']}")
            print(f"   Mô tả: {issue['message']}")
            if 'code' in issue and issue['code']:
                print(f"   Đoạn code: {issue['code']}")
            if 'context' in issue and issue['context']:
                print(f"   Ngữ cảnh:\n{issue['context']}")
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(issues, f, ensure_ascii=False, indent=2)
            print(f"\nĐã lưu kết quả vào file {args.output}")
    else:
        print("Không tìm thấy vấn đề nào về lưu trữ thông tin cá nhân nhạy cảm không đúng cách.")

if __name__ == "__main__":
    main() 