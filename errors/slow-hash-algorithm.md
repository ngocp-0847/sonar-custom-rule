# Hướng dẫn về tăng cường bảo mật thông qua kỹ thuật hash chậm

Khi xây dựng hệ thống bảo mật, việc bảo vệ mật khẩu người dùng khỏi các cuộc tấn công brute-force là vô cùng quan trọng. Một phương pháp hiệu quả là sử dụng các thuật toán hash chậm với số vòng lặp cao. Dưới đây là hướng dẫn chi tiết về cách triển khai đúng cách.

## Tại sao cần sử dụng hash chậm?

Khi một hệ thống bị tấn công và cơ sở dữ liệu mật khẩu bị rò rỉ, kẻ tấn công sẽ cố gắng "crack" các hash mật khẩu thông qua tấn công brute-force hoặc dictionary. Các thuật toán hash chậm được thiết kế để làm tăng chi phí tính toán của mỗi lần thử, khiến việc tấn công trở nên khó khăn hơn nhiều.

## Các thuật toán hash chậm phổ biến

### 1. PBKDF2 (Password-Based Key Derivation Function 2)

PBKDF2 là thuật toán cơ bản sử dụng phương pháp lặp đi lặp lại một hàm hash như SHA-256.

#### Cấu hình đề xuất:
- **Hiện tại**: 100,000 vòng
- **Khuyến nghị**: ≥ 310,000 vòng

#### Ví dụ triển khai trong Python:

```python
import hashlib
import os
import binascii

def hash_password_pbkdf2(password, salt=None, iterations=310000):
    if salt is None:
        salt = os.urandom(16)  # 16 bytes = 128 bits
    
    # Tạo hash với PBKDF2 sử dụng HMAC-SHA256
    pw_hash = hashlib.pbkdf2_hmac('sha256', 
                                  password.encode('utf-8'), 
                                  salt, 
                                  iterations,
                                  dklen=32)  # 32 bytes = 256 bits
    
    # Chuyển đổi sang định dạng lưu trữ
    storage = {
        'algorithm': 'pbkdf2_sha256',
        'iterations': iterations,
        'salt': binascii.hexlify(salt).decode('ascii'),
        'hash': binascii.hexlify(pw_hash).decode('ascii')
    }
    
    return storage

# Sử dụng hàm
password = "mật_khẩu_phức_tạp"
hashed_password = hash_password_pbkdf2(password)
print(hashed_password)
```

### 2. bcrypt

bcrypt là thuật toán được thiết kế đặc biệt để hash mật khẩu với cơ chế chống lại tấn công brute-force.

#### Cấu hình đề xuất:
- **Hiện tại**: rounds = 10-14
- **Khuyến nghị**: ≥ 12 rounds (tương đương với 2^12 = 4096 vòng lặp)

#### Ví dụ triển khai trong Python:

```python
import bcrypt

def hash_password_bcrypt(password, rounds=12):
    # Mã hóa mật khẩu với số rounds được chỉ định
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    return {
        'algorithm': 'bcrypt',
        'rounds': rounds,
        'hash': hashed.decode('ascii')
    }

# Sử dụng hàm
password = "mật_khẩu_phức_tạp"
hashed_password = hash_password_bcrypt(password, rounds=12)
print(hashed_password)

# Xác thực mật khẩu
def verify_password_bcrypt(password, stored_hash):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('ascii'))
```

### 3. Argon2

Argon2 là thuật toán đã chiến thắng cuộc thi Password Hashing Competition năm 2015 và hiện được khuyến nghị sử dụng.

#### Cấu hình đề xuất:
- **Hiện tại**: m=65536, t=3, p=4
- Trong đó:
  - m: bộ nhớ sử dụng (KiB)
  - t: số vòng lặp 
  - p: mức độ song song

#### Ví dụ triển khai trong Python:

```python
import argon2

def hash_password_argon2(password, salt=None):
    # Tạo salt ngẫu nhiên nếu không được cung cấp
    if salt is None:
        salt = os.urandom(16)
        
    # Thiết lập tham số với cấu hình khuyến nghị
    ph = argon2.PasswordHasher(
        memory_cost=65536,  # 64 MB
        time_cost=3,        # 3 vòng lặp
        parallelism=4,      # 4 luồng song song
        hash_len=32,        # Độ dài hash 32 byte
        salt_len=16         # Độ dài salt 16 byte
    )
    
    # Tạo hash
    hash_str = ph.hash(password)
    
    return {
        'algorithm': 'argon2id',
        'parameters': {
            'memory_cost': 65536,
            'time_cost': 3,
            'parallelism': 4
        },
        'hash': hash_str
    }

# Sử dụng hàm
password = "mật_khẩu_phức_tạp"
hashed_password = hash_password_argon2(password)
print(hashed_password)

# Xác thực mật khẩu
def verify_password_argon2(password, hash_str):
    ph = argon2.PasswordHasher()
    try:
        ph.verify(hash_str, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
```

## Cách kiểm tra và khắc phục lỗi

### Cách kiểm tra cấu hình hiện tại

1. **PBKDF2**: Kiểm tra tham số iterations trong mã của bạn
2. **bcrypt**: Kiểm tra tham số rounds (thường là một số từ 10-14)
3. **Argon2**: Kiểm tra các tham số m (memory), t (time), p (parallelism)

### Triển khai kiểm tra tự động

## Các trường hợp thực tế

### Ví dụ thực tế: Xác thực người dùng trong Django

Django, một framework web Python phổ biến, sử dụng PBKDF2 mặc định. Dưới đây là cách cấu hình số vòng lặp:

```python
# settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]

# Tăng số vòng lặp từ mặc định (tùy phiên bản Django) lên 310,000
PASSWORD_HASHERS = [
    {
        'ALGORITHM': 'pbkdf2_sha256',
        'ITERATIONS': 310000,
        'SALT_LENGTH': 16,
    },
]
```

### Ví dụ thực tế: Xác thực trong Node.js

```javascript
const bcrypt = require('bcrypt');
const saltRounds = 12; // Đề xuất: >= 12

// Hash mật khẩu
async function hashPassword(password) {
  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (err) {
    console.error(err);
    throw err;
  }
}

// Xác thực mật khẩu
async function verifyPassword(password, hash) {
  try {
    const match = await bcrypt.compare(password, hash);
    return match;
  } catch (err) {
    console.error(err);
    throw err;
  }
}
```

## Cân nhắc về hiệu suất

Tăng số vòng lặp sẽ ảnh hưởng đến hiệu suất của hệ thống. Bảng dưới đây cung cấp ước tính thời gian xử lý trên một máy tính hiện đại:

| Thuật toán | Cấu hình | Thời gian xử lý (ước tính) |
|------------|----------|----------------------------|
| PBKDF2     | 100,000 vòng | ~100ms |
| PBKDF2     | 310,000 vòng | ~300ms |
| bcrypt     | rounds=10 | ~80ms |
| bcrypt     | rounds=12 | ~320ms |
| Argon2     | m=65536, t=3, p=4 | ~250ms |

Đối với các hệ thống có lưu lượng cao, bạn có thể cân nhắc sử dụng hàng đợi hoặc xử lý bất đồng bộ để xử lý việc xác thực mật khẩu.

## Kết luận

Việc sử dụng thuật toán hash chậm với số vòng lặp cao là biện pháp bảo vệ quan trọng chống lại các cuộc tấn công brute-force. Khuyến nghị:

1. Đối với PBKDF2: Ít nhất 310,000 vòng lặp
2. Đối với bcrypt: Ít nhất 12 rounds
3. Đối với Argon2: m=65536, t=3, p=4 hoặc cao hơn

Thực hiện các biện pháp này sẽ giúp bảo vệ dữ liệu người dùng ngay cả trong trường hợp cơ sở dữ liệu bị xâm nhập.


## Code kiểm tra tự động.

```python
import re
import sys
import json
import os

def check_pbkdf2_iterations(code_str):
    """Kiểm tra số vòng lặp PBKDF2 trong mã nguồn"""
    # Tìm kiếm các mẫu thông dụng
    patterns = [
        r'iterations\s*=\s*(\d+)',
        r'pbkdf2_hmac\([^,]+,[^,]+,[^,]+,\s*(\d+)',
        r'PBKDF2ITERATIONS\s*=\s*(\d+)'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, code_str)
        if matches:
            return int(matches[0])
    
    return None

def check_bcrypt_rounds(code_str):
    """Kiểm tra số rounds của bcrypt trong mã nguồn"""
    patterns = [
        r'rounds\s*=\s*(\d+)',
        r'gensalt\(\s*rounds\s*=\s*(\d+)',
        r'BCRYPT_ROUNDS\s*=\s*(\d+)'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, code_str)
        if matches:
            return int(matches[0])
    
    return None

def check_argon2_params(code_str):
    """Kiểm tra tham số Argon2 trong mã nguồn"""
    memory_patterns = [r'memory_cost\s*=\s*(\d+)', r'm\s*=\s*(\d+)']
    time_patterns = [r'time_cost\s*=\s*(\d+)', r't\s*=\s*(\d+)']
    parallelism_patterns = [r'parallelism\s*=\s*(\d+)', r'p\s*=\s*(\d+)']
    
    memory = None
    time = None
    parallelism = None
    
    for pattern in memory_patterns:
        matches = re.findall(pattern, code_str)
        if matches:
            memory = int(matches[0])
            break
    
    for pattern in time_patterns:
        matches = re.findall(pattern, code_str)
        if matches:
            time = int(matches[0])
            break
    
    for pattern in parallelism_patterns:
        matches = re.findall(pattern, code_str)
        if matches:
            parallelism = int(matches[0])
            break
    
    return {
        'memory_cost': memory,
        'time_cost': time,
        'parallelism': parallelism
    }

def evaluate_security(results):
    """Đánh giá mức độ bảo mật dựa trên kết quả kiểm tra"""
    issues = []
    recommendations = []
    
    # Kiểm tra PBKDF2
    if results['pbkdf2_iterations'] is not None:
        if results['pbkdf2_iterations'] < 310000:
            issues.append(f"PBKDF2: Sử dụng {results['pbkdf2_iterations']} vòng lặp (khuyến nghị >= 310,000)")
            recommendations.append("Tăng số vòng lặp PBKDF2 lên ít nhất 310,000")
    
    # Kiểm tra bcrypt
    if results['bcrypt_rounds'] is not None:
        if results['bcrypt_rounds'] < 12:
            issues.append(f"bcrypt: Sử dụng rounds={results['bcrypt_rounds']} (khuyến nghị >= 12)")
            recommendations.append("Tăng số rounds của bcrypt lên ít nhất 12")
    
    # Kiểm tra Argon2
    argon2 = results['argon2_params']
    if argon2['memory_cost'] is not None and argon2['time_cost'] is not None and argon2['parallelism'] is not None:
        if argon2['memory_cost'] < 65536 or argon2['time_cost'] < 3 or argon2['parallelism'] < 4:
            issues.append(f"Argon2: Sử dụng m={argon2['memory_cost']}, t={argon2['time_cost']}, p={argon2['parallelism']} (khuyến nghị m>=65536, t>=3, p>=4)")
            recommendations.append("Cấu hình Argon2 với m=65536, t=3, p=4 hoặc cao hơn")
    
    return {
        'issues': issues,
        'recommendations': recommendations
    }

def scan_directory(directory_path):
    """Quét toàn bộ thư mục để tìm và kiểm tra các tệp mã nguồn"""
    results = {
        'pbkdf2_iterations': None,
        'bcrypt_rounds': None,
        'argon2_params': {
            'memory_cost': None,
            'time_cost': None,
            'parallelism': None
        },
        'files_scanned': 0
    }
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith(('.py', '.js', '.php', '.rb', '.java')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code_str = f.read()
                        
                    # Kiểm tra PBKDF2
                    pbkdf2_iter = check_pbkdf2_iterations(code_str)
                    if pbkdf2_iter and (results['pbkdf2_iterations'] is None or pbkdf2_iter < results['pbkdf2_iterations']):
                        results['pbkdf2_iterations'] = pbkdf2_iter
                    
                    # Kiểm tra bcrypt
                    bcrypt_r = check_bcrypt_rounds(code_str)
                    if bcrypt_r and (results['bcrypt_rounds'] is None or bcrypt_r < results['bcrypt_rounds']):
                        results['bcrypt_rounds'] = bcrypt_r
                    
                    # Kiểm tra Argon2
                    argon2_p = check_argon2_params(code_str)
                    if argon2_p['memory_cost'] and (results['argon2_params']['memory_cost'] is None or argon2_p['memory_cost'] < results['argon2_params']['memory_cost']):
                        results['argon2_params']['memory_cost'] = argon2_p['memory_cost']
                    if argon2_p['time_cost'] and (results['argon2_params']['time_cost'] is None or argon2_p['time_cost'] < results['argon2_params']['time_cost']):
                        results['argon2_params']['time_cost'] = argon2_p['time_cost']
                    if argon2_p['parallelism'] and (results['argon2_params']['parallelism'] is None or argon2_p['parallelism'] < results['argon2_params']['parallelism']):
                        results['argon2_params']['parallelism'] = argon2_p['parallelism']
                    
                    results['files_scanned'] += 1
                except Exception as e:
                    print(f"Lỗi khi đọc file {file_path}: {e}")
    
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Sử dụng: python hash_security_checker.py <đường_dẫn_thư_mục>")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    results = scan_directory(directory_path)
    
    print(f"\n===== KẾT QUẢ KIỂM TRA BẢO MẬT HASH =====")
    print(f"Đã quét {results['files_scanned']} files\n")
    
    print("Cấu hình hiện tại:")
    print(f"PBKDF2 iterations: {results['pbkdf2_iterations'] or 'Không tìm thấy'}")
    print(f"bcrypt rounds: {results['bcrypt_rounds'] or 'Không tìm thấy'}")
    
    argon2 = results['argon2_params']
    print(f"Argon2 params: m={argon2['memory_cost'] or 'N/A'}, t={argon2['time_cost'] or 'N/A'}, p={argon2['parallelism'] or 'N/A'}")
    
    evaluation = evaluate_security(results)
    
    if evaluation['issues']:
        print("\nCÁC VẤN ĐỀ PHÁT HIỆN:")
        for issue in evaluation['issues']:
            print(f"- {issue}")
        
        print("\nKHUYẾN NGHỊ:")
        for rec in evaluation['recommendations']:
            print(f"- {rec}")
    else:
        print("\nCấu hình bảo mật hash đáp ứng các khuyến nghị tối thiểu.")
```