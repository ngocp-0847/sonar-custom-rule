// massParmAssignment.ts - Ví dụ về lỗi Mass Parameter Assignment

// Model User với các thuộc tính nhạy cảm
class User {
  id: number;
  username: string;
  email: string;
  role: string = 'user'; // Mặc định là người dùng thông thường
  isAdmin: boolean = false;
  balance: number = 0;

  constructor(id: number, username: string, email: string) {
    this.id = id;
    this.username = username;
    this.email = email;
  }

  // Phương thức updateProfile có lỗ hổng Mass Parameter Assignment
  updateProfile(userData: any): void {
    // KHÔNG AN TOÀN: Cập nhật tất cả thuộc tính từ userData mà không kiểm tra
    Object.assign(this, userData);
    console.log('Đã cập nhật thông tin người dùng:', this);
  }

  // Phương thức an toàn để cập nhật thông tin người dùng
  secureUpdateProfile(userData: { username?: string; email?: string }): void {
    // AN TOÀN: Chỉ cập nhật các trường được cho phép
    if (userData.username) this.username = userData.username;
    if (userData.email) this.email = userData.email;
    console.log('Đã cập nhật thông tin người dùng an toàn:', this);
  }
}

// Mô phỏng một server API Express
class UserController {
  static updateUserProfile(user: User, requestBody: any): void {
    console.log('Yêu cầu cập nhật từ client:', requestBody);
    
    // Phiên bản không an toàn
    console.log('\n[KHÔNG AN TOÀN] Cập nhật với Mass Parameter Assignment:');
    user.updateProfile(requestBody);
    
    // Phiên bản an toàn
    console.log('\n[AN TOÀN] Cập nhật với kiểm soát trường:');
    user.secureUpdateProfile(requestBody);
  }
}

// Minh họa lỗ hổng Mass Parameter Assignment
console.log('===== LỖ HỔNG MASS PARAMETER ASSIGNMENT =====');

// Tạo một người dùng
const user = new User(1, 'usertest', 'user@example.com');
console.log('User ban đầu:', user);

// Tình huống 1: Cập nhật thông tin bình thường
console.log('\n--- Tình huống 1: Cập nhật thông tin hợp lệ ---');
UserController.updateUserProfile(user, {
  username: 'newusername',
  email: 'newemail@example.com'
});

// Reset user để minh họa tình huống tấn công
const user2 = new User(2, 'victim', 'victim@example.com');
console.log('\n--- Tình huống 2: CUỘC TẤN CÔNG escalation quyền ---');
console.log('User ban đầu:', user2);

// Tình huống 2: Attacker thực hiện tấn công leo thang đặc quyền
UserController.updateUserProfile(user2, {
  username: 'hacker',
  email: 'hacker@evil.com',
  role: 'admin',
  isAdmin: true,
  balance: 999999
});

// Minh họa cách phòng tránh
console.log('\n===== CÁCH PHÒNG TRÁNH =====');
console.log('1. Chỉ định rõ ràng các trường được phép cập nhật (Allow List)');
console.log('2. Sử dụng TypeScript để xác định kiểu dữ liệu cho các tham số');
console.log('3. Không sử dụng Object.assign() trực tiếp với dữ liệu đầu vào');
console.log('4. Thực hiện xác thực dữ liệu trước khi áp dụng thay đổi');

// Triển khai với TypeScript tốt hơn
interface UserUpdateDto {
  username?: string;
  email?: string;
  // Lưu ý: role và isAdmin KHÔNG có trong interface này
}

// Ví dụ với class mới và tốt hơn
class SecureUser {
  private id: number;
  private username: string;
  private email: string;
  private role: string = 'user';
  private isAdmin: boolean = false;
  private balance: number = 0;

  constructor(id: number, username: string, email: string) {
    this.id = id;
    this.username = username;
    this.email = email;
  }

  // Phương thức an toàn: chỉ định rõ kiểu dữ liệu và giới hạn các trường
  updateProfile(userData: UserUpdateDto): void {
    // Chỉ cập nhật các trường được cho phép bởi interface
    if (userData.username) this.username = userData.username;
    if (userData.email) this.email = userData.email;
    
    console.log('Thông tin người dùng sau khi cập nhật an toàn:', {
      id: this.id,
      username: this.username,
      email: this.email,
      role: this.role, // Chỉ hiển thị, không thể thay đổi từ bên ngoài
      isAdmin: this.isAdmin,
      balance: this.balance
    });
  }
  
  // Getter method cho các trường private
  getInfo() {
    return {
      id: this.id,
      username: this.username,
      email: this.email,
      role: this.role,
      isAdmin: this.isAdmin
    };
  }
}

console.log('\n--- Demo giải pháp với TypeScript ---');
const secureUser = new SecureUser(3, 'secureuser', 'secure@example.com');
console.log('Secure User ban đầu:', secureUser.getInfo());

// Cố gắng cập nhật với dữ liệu độc hại
console.log('\nCố gắng thực hiện tấn công:');
const maliciousData: any = {
  username: 'attackerfailed',
  email: 'fail@evil.com',
  role: 'admin', // Sẽ bị bỏ qua nhờ interface
  isAdmin: true,  // Sẽ bị bỏ qua nhờ interface
  balance: 99999  // Sẽ bị bỏ qua nhờ interface
};

secureUser.updateProfile(maliciousData);
console.log('Secure User sau tấn công:', secureUser.getInfo()); 