<?php
/**
 * File ví dụ chứa các lỗi Mass Assignment để kiểm tra công cụ
 */

// Ví dụ 1: Sử dụng extract() với dữ liệu người dùng
function example1() {
    // Lỗi: Sử dụng extract trực tiếp từ $_POST
    extract($_POST);
    
    // Sử dụng các biến đã được trích xuất
    echo $username;
    echo $email;
}

// Ví dụ 2: Gán trực tiếp từ $_GET
function example2() {
    // Lỗi: Gán trực tiếp từ $_GET
    $user = $_GET['user'];
    $isAdmin = $_GET['isAdmin']; // Nguy hiểm: Người dùng có thể tự đặt quyền admin
}

// Ví dụ 3: Gán trực tiếp dữ liệu $_POST vào đối tượng
function example3($user) {
    // Lỗi: Gán toàn bộ $_POST vào đối tượng
    $user->update($_POST);
}

// Ví dụ 4: Sử dụng Laravel eloquent với mass assignment
function example4() {
    // Lỗi: Tạo bản ghi mới với toàn bộ dữ liệu từ request
    $user = User::create($_REQUEST);
    
    // Lỗi: Cập nhật đối tượng với toàn bộ dữ liệu từ request
    $user->update($_POST);
    
    // Lỗi: Điền toàn bộ dữ liệu vào model
    $user->fill($_REQUEST);
}

// Ví dụ 5: CodeIgniter ORM với mass assignment
function example5($this) {
    // Lỗi: Insert toàn bộ dữ liệu từ POST
    $this->db->insert('users', $_POST);
    
    // Lỗi: Update bản ghi với toàn bộ dữ liệu từ POST
    $this->db->update('users', $_POST, ['id' => 1]);
}

// Ví dụ 6: CakePHP với mass assignment
function example6($this) {
    // Lỗi: Save toàn bộ dữ liệu từ request
    $user = $this->Users->patchEntity($user, $this->request->data);
    $this->Users->save($this->request->data);
}

// Ví dụ 7: Symfony form binding
function example7($form, $request) {
    // Lỗi: Bind request trực tiếp vào form
    $form->bindRequest($request);
}

// Ví dụ 8: Array merge với dữ liệu người dùng
function example8() {
    $defaults = ['role' => 'user', 'active' => true];
    
    // Lỗi: Merge với $_POST, có thể ghi đè các giá trị mặc định
    $userData = array_merge($defaults, $_POST);
}

// Cách khắc phục: Sử dụng danh sách cho phép
function goodExample1() {
    // Tốt: Chỉ cho phép một số trường cụ thể
    $allowedFields = ['username', 'email', 'name'];
    $userData = [];
    
    foreach ($allowedFields as $field) {
        if (isset($_POST[$field])) {
            $userData[$field] = $_POST[$field];
        }
    }
    
    // Bây giờ $userData chỉ chứa các trường an toàn
    $user->update($userData);
}

// Cách khắc phục: Gán riêng từng trường và kiểm tra
function goodExample2() {
    // Tốt: Kiểm tra và gán thủ công các trường
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $email = isset($_POST['email']) ? $_POST['email'] : '';
    
    // Kiểm tra dữ liệu trước khi sử dụng
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Xử lý dữ liệu hợp lệ
    }
}

// Ví dụ 9: Lỗi lưu trữ dữ liệu nhạy cảm trong cache
function cachingExampleWithSensitiveData() {
    // Lấy thông tin người dùng từ database
    $userInfo = [
        'username' => 'admin',
        'password' => 'hashed_password',
        'credit_card' => '1234-5678-9012-3456',
        'social_security' => '123-45-6789',
        'address' => '123 Security St, Privacy City',
        'email' => 'admin@example.com',
        'api_key' => 'sk_live_abcdef123456'
    ];
    
    // Lỗi 1: Lưu trữ dữ liệu nhạy cảm vào cache mà không xóa trường nhạy cảm
    Cache::put('user_profile', $userInfo, 3600);
    
    // Lỗi 2: Lưu trữ thông tin nhạy cảm vào session
    $_SESSION['user_data'] = $userInfo;
    
    // Lỗi 3: Trả về dữ liệu nhạy cảm không có header ngăn chặn cache
    header('Content-Type: application/json');
    echo json_encode($userInfo);
    
    // Lỗi 4: Lưu trữ token truy cập trong cache mà không có thời gian hết hạn ngắn
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    $redis->set('auth_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
    // Thiếu thiết lập thời gian hết hạn: $redis->expire('auth_token', 3600);
    
    // Lỗi 5: Set cookie chứa thông tin nhạy cảm mà không có flag HttpOnly và Secure
    setcookie('user_auth', json_encode(['email' => 'admin@example.com', 'api_key' => 'sk_live_abcdef123456']), time() + 86400);
}

// Cách khắc phục cho các lỗi lưu trữ dữ liệu nhạy cảm
function secureDataCachingExample() {
    // Lấy thông tin người dùng từ database
    $userInfo = [
        'username' => 'admin',
        'password' => 'hashed_password',
        'credit_card' => '1234-5678-9012-3456',
        'social_security' => '123-45-6789',
        'address' => '123 Security St, Privacy City',
        'email' => 'admin@example.com',
        'api_key' => 'sk_live_abcdef123456'
    ];
    
    // Tốt: Chỉ lưu trữ dữ liệu không nhạy cảm vào cache
    $safeUserInfo = [
        'username' => $userInfo['username'],
        'display_name' => 'Admin User',
        'preferences' => ['theme' => 'dark', 'language' => 'vi']
    ];
    Cache::put('user_profile', $safeUserInfo, 1800); // Thời gian ngắn hơn: 30 phút
    
    // Tốt: Sử dụng headers ngăn chặn cache khi trả về dữ liệu nhạy cảm
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('Content-Type: application/json');
    echo json_encode($userInfo);
    
    // Tốt: Lưu token với thời gian hết hạn ngắn
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    $redis->set('auth_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
    $redis->expire('auth_token', 900); // 15 phút
    
    // Tốt: Cookie an toàn với HttpOnly và Secure flags
    setcookie(
        'user_session',
        'session_id_only_no_sensitive_data',
        [
            'expires' => time() + 3600,
            'path' => '/',
            'domain' => 'example.com',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]
    );
}

/**
 * CÁC VÍ DỤ VỀ LỖI LƯU TRỮ OTP PLAINTEXT
 */

// Ví dụ 1: Lưu OTP dưới dạng plaintext trong database (PHP)
function otpExample1() {
    // Tạo OTP
    $otp = rand(100000, 999999);
    $userId = $_GET['user_id'];
    $email = $_GET['email'];
    
    // LỖI: Lưu OTP dưới dạng plaintext trong database
    $sql = "INSERT INTO otp_table (user_id, otp, created_at) VALUES ('$userId', '$otp', NOW())";
    $conn->query($sql);
    
    // Gửi OTP qua email
    sendEmail($email, "Your OTP is: " . $otp);
    
    return "OTP đã được gửi đến email của bạn.";
}

// Ví dụ 2: Xác thực OTP bằng cách so sánh plaintext
function otpExample2() {
    $inputOtp = $_POST['otp'];
    $userId = $_POST['user_id'];
    
    // LỖI: Truy vấn OTP dưới dạng plaintext để so sánh
    $sql = "SELECT * FROM otp_table WHERE user_id = '$userId' AND otp = '$inputOtp' AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
    $result = $conn->query($sql);
    
    if ($result->num_rows > 0) {
        // OTP hợp lệ
        $sql = "DELETE FROM otp_table WHERE user_id = '$userId'";
        $conn->query($sql);
        return "Xác thực thành công!";
    } else {
        return "OTP không hợp lệ hoặc đã hết hạn!";
    }
}

// Ví dụ 3: Lưu OTP vào session
function otpExample3() {
    // Tạo OTP
    $otp = generateRandomOTP();
    $email = $_POST['email'];
    
    // LỖI: Lưu OTP dưới dạng plaintext trong session
    $_SESSION['user_otp'] = $otp;
    $_SESSION['otp_time'] = time();
    
    // Gửi OTP qua email
    sendEmail($email, "Your OTP is: " . $otp);
    
    return "OTP đã được gửi đến email của bạn.";
}

// Ví dụ 4: Lưu OTP trong log
function otpExample4() {
    $otp = sprintf('%06d', rand(0, 999999));
    $userId = $_POST['user_id'];
    $phone = $_POST['phone'];
    
    // LỖI: Ghi OTP vào log
    error_log("Sent OTP $otp to user $userId at phone $phone");
    
    // Lưu OTP vào database
    $stmt = $pdo->prepare("INSERT INTO otp_table (user_id, otp, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))");
    $stmt->execute([$userId, $otp]);
    
    // Gửi OTP qua SMS
    sendSMS($phone, "Your OTP is: " . $otp);
    
    return "OTP đã được gửi đến điện thoại của bạn.";
}

// Ví dụ 5: Sử dụng ORM để lưu OTP (Laravel)
function otpExample5() {
    // Tạo OTP
    $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $user = Auth::user();
    
    // LỖI: Lưu OTP dưới dạng plaintext sử dụng ORM
    OTP::create([
        'user_id' => $user->id,
        'otp' => $otp,
        'expires_at' => now()->addMinutes(10)
    ]);
    
    // Gửi OTP
    $user->notify(new OTPNotification($otp));
    
    return response()->json(['message' => 'OTP đã được gửi']);
}

/**
 * CÁCH KHẮC PHỤC CHO CÁC LỖI LƯU TRỮ OTP PLAINTEXT
 */

// Cách khắc phục 1: Sử dụng hash để lưu OTP
function secureOtpExample1() {
    // Tạo OTP
    $otp = rand(100000, 999999);
    $userId = $_GET['user_id'];
    $email = $_GET['email'];
    
    // Tạo hash từ OTP và user_id (như một salt)
    $hashedOtp = password_hash($otp . $userId, PASSWORD_BCRYPT);
    
    // TỐT: Lưu hash của OTP thay vì plaintext
    $sql = "INSERT INTO otp_table (user_id, otp_hash, created_at) VALUES ('$userId', '$hashedOtp', NOW())";
    $conn->query($sql);
    
    // Gửi OTP qua email
    sendEmail($email, "Your OTP is: " . $otp);
    
    return "OTP đã được gửi đến email của bạn.";
}

// Cách khắc phục 2: Xác thực OTP bằng cách so sánh hash
function secureOtpExample2() {
    $inputOtp = $_POST['otp'];
    $userId = $_POST['user_id'];
    
    // TỐT: Lấy hash OTP từ database để so sánh
    $sql = "SELECT otp_hash FROM otp_table WHERE user_id = '$userId' AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
    $result = $conn->query($sql);
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $storedHash = $row['otp_hash'];
        
        // So sánh OTP đầu vào với hash đã lưu
        if (password_verify($inputOtp . $userId, $storedHash)) {
            // OTP hợp lệ
            $sql = "DELETE FROM otp_table WHERE user_id = '$userId'";
            $conn->query($sql);
            return "Xác thực thành công!";
        }
    }
    
    return "OTP không hợp lệ hoặc đã hết hạn!";
}

// Cách khắc phục 3: HMAC để bảo vệ OTP trong session
function secureOtpExample3() {
    // Tạo OTP
    $otp = generateRandomOTP();
    $email = $_POST['email'];
    $userId = getUserIdFromEmail($email);
    
    // Tạo khóa bí mật cho session này
    if (!isset($_SESSION['otp_secret'])) {
        $_SESSION['otp_secret'] = bin2hex(random_bytes(32));
    }
    
    // TỐT: Lưu HMAC của OTP trong session
    $_SESSION['otp_hmac'] = hash_hmac('sha256', $otp . $userId, $_SESSION['otp_secret']);
    $_SESSION['otp_time'] = time();
    
    // Gửi OTP qua email
    sendEmail($email, "Your OTP is: " . $otp);
    
    return "OTP đã được gửi đến email của bạn.";
}

// Cách khắc phục 4: Không ghi OTP vào log
function secureOtpExample4() {
    $otp = sprintf('%06d', rand(0, 999999));
    $userId = $_POST['user_id'];
    $phone = $_POST['phone'];
    
    // TỐT: Ghi log mà không tiết lộ OTP
    error_log("OTP sent to user $userId at phone " . substr($phone, 0, 3) . "****" . substr($phone, -2));
    
    // Lưu hash của OTP vào database
    $hashedOtp = password_hash($otp . $userId, PASSWORD_BCRYPT);
    $stmt = $pdo->prepare("INSERT INTO otp_table (user_id, otp_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))");
    $stmt->execute([$userId, $hashedOtp]);
    
    // Gửi OTP qua SMS
    sendSMS($phone, "Your OTP is: " . $otp);
    
    return "OTP đã được gửi đến điện thoại của bạn.";
}

// Cách khắc phục 5: Sử dụng ORM để lưu hash OTP (Laravel)
function secureOtpExample5() {
    // Tạo OTP
    $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $user = Auth::user();
    
    // TỐT: Lưu hash của OTP sử dụng ORM
    OTP::create([
        'user_id' => $user->id,
        'otp_hash' => Hash::make($otp . $user->id),
        'expires_at' => now()->addMinutes(10)
    ]);
    
    // Gửi OTP
    $user->notify(new OTPNotification($otp));
    
    return response()->json(['message' => 'OTP đã được gửi']);
}

// Hàm phụ trợ
function generateRandomOTP() {
    return sprintf("%06d", mt_rand(0, 999999));
}

function getUserIdFromEmail($email) {
    // Giả lập lấy user ID từ email
    return md5($email);
}
?> 