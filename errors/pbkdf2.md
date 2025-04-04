### 🔹 PBKDF2 (Password-Based Key Derivation Function 2) – Giải thích bằng Toán và Ví dụ 🔹  

PBKDF2 là một thuật toán dẫn xuất khóa (Key Derivation Function - KDF) được sử dụng để tạo khóa mật mã mạnh từ mật khẩu. PBKDF2 được định nghĩa trong **RFC 2898** và thường được sử dụng trong bảo mật mật khẩu (password hashing) hoặc tạo khóa mã hóa từ mật khẩu.  

---

## 🚀 1. Công thức Toán học của PBKDF2  

PBKDF2 sử dụng một hàm băm mật mã (như **HMAC-SHA256** hoặc **HMAC-SHA512**) và thực hiện lặp lại nhiều lần để làm cho việc tấn công brute-force khó khăn hơn.

### Công thức tính toán:  
Cho một mật khẩu $P$, một **Salt** $S$, số vòng lặp $c$, và độ dài khóa đầu ra $dkLen$:

$$
PBKDF2(P, S, c, dkLen) = T_1 || T_2 || \dots || T_n
$$

trong đó:

$$
T_i = F(P, S, c, i)
$$

Hàm dẫn xuất khóa $F(P, S, c, i)$ được định nghĩa như sau:

$$
F(P, S, c, i) = U_1 \oplus U_2 \oplus \dots \oplus U_c
$$

với:

$$
U_1 = PRF(P, S || INT(i))
$$

$$
U_j = PRF(P, U_{j-1}), \quad \text{với } j \geq 2
$$

Trong đó:  
- **PRF** (Pseudo-Random Function) thường là **HMAC-SHA256** hoặc **HMAC-SHA512**  
- **Salt** $S$ giúp tránh tấn công Rainbow Table  
- $c$ là số lần lặp, giúp làm chậm tốc độ dò mật khẩu  
- $dkLen$ là độ dài khóa đầu ra  
- $\oplus$ là phép XOR  

---

## 📌 2. Ví dụ minh họa PBKDF2  

**Giả sử chúng ta có:**  
- Mật khẩu (**Password**) = `"password123"`  
- Salt = `"salty"` (Được chuyển thành dạng bytes)  
- Hàm băm = `HMAC-SHA256`  
- Số vòng lặp (**Iterations**) = `10,000`  
- Độ dài khóa cần tạo (**dkLen**) = `32` bytes  

Dưới đây là cách tính từng bước:

### 🔹 Bước 1: Tạo $U_1$
$$
U_1 = HMAC_{SHA256}(P, S || INT(1))
$$

### 🔹 Bước 2: Tạo $U_2$, $U_3$, ..., $U_c$
$$
U_2 = HMAC_{SHA256}(P, U_1)
$$

$$
U_3 = HMAC_{SHA256}(P, U_2)
$$

…

$$
U_{10000} = HMAC_{SHA256}(P, U_{9999})
$$

### 🔹 Bước 3: Tính giá trị khóa đầu ra $T_i$
$$
T_1 = U_1 \oplus U_2 \oplus ... \oplus U_c
$$

Ghép nhiều $T_i$ lại để có đủ độ dài **32 bytes**.

---

## 🛠 3. Code Python thực tế  

```python
import hashlib
import binascii
from hashlib import pbkdf2_hmac

# Thông số đầu vào
password = "password123".encode()  # Chuyển thành bytes
salt = "salty".encode()
iterations = 10000
dkLen = 32  # Độ dài khóa đầu ra (32 bytes)

# Tính toán PBKDF2
derived_key = pbkdf2_hmac('sha256', password, salt, iterations, dkLen)

# Chuyển thành hex để dễ đọc
print("Derived Key:", binascii.hexlify(derived_key).decode())
```

---

## ✅ 4. Kết luận  
- PBKDF2 giúp tạo khóa mật mã mạnh từ mật khẩu bằng cách lặp lại nhiều lần.  
- Công thức sử dụng **HMAC với Salt** để chống tấn công Rainbow Table.  
- PBKDF2 được dùng phổ biến trong **bảo mật mật khẩu** (bcrypt, scrypt, Argon2 cũng là các KDF tương tự).  
- Dùng số vòng lặp cao (ví dụ: `100,000+`) giúp chống brute-force tốt hơn.  

⏳ **PBKDF2 chậm nhưng an toàn, phù hợp cho xác thực mật khẩu!** 🚀