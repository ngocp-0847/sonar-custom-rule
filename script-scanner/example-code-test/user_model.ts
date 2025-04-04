// Ví dụ mã TypeScript có lỗi về lưu trữ thông tin cá nhân nhạy cảm không đúng cách

// Mock imports (giả lập module) để tránh lỗi linter
// @ts-ignore
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';
// @ts-ignore
import * as mongoose from 'mongoose';
// @ts-ignore
import Redis from 'redis';

// Mock repository
const userRepository = {
  save: (user: any) => Promise.resolve(user)
};

// LỖI: Entity chứa thông tin nhạy cảm mà không có trường thời hạn lưu trữ
@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  password: string;

  @Column()
  email: string;

  @Column()
  fullName: string;

  @Column()
  dateOfBirth: Date;

  @Column()
  socialSecurityNumber: string;

  @Column()
  passportNumber: string;

  @Column()
  homeAddress: string;

  @Column()
  phoneNumber: string;

  @Column()
  creditCardNumber: string;

  @Column()
  cvv: string;

  // LỖI: Không có trường cho thời hạn lưu trữ
  @Column()
  createdAt: Date = new Date();

  // LỖI: Không có phương thức xử lý việc xóa dữ liệu hết hạn
}

// LỖI: Interface cũng định nghĩa dữ liệu nhạy cảm mà không có thời hạn lưu trữ
export interface UserProfile {
  id: number;
  username: string;
  email: string;
  fullName: string;
  dateOfBirth: string;
  socialSecurityNumber: string;
  passportNumber: string;
  addressInformation: {
    street: string;
    city: string;
    country: string;
  };
  bankAccount: string;
  // LỖI: Không có trường cho thời hạn lưu trữ
}

// LỖI: Schema Mongoose không có cơ chế tự động xóa dữ liệu
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
  fullName: String,
  dateOfBirth: Date,
  socialSecurityNumber: String,
  creditCardNumber: String,
  createdAt: { type: Date, default: Date.now }
  // LỖI: Không có trường expires hoặc TTL index
});

// LỖI: Service lưu trữ dữ liệu nhạy cảm mà không phân loại và không có cơ chế xóa
export class UserService {
  // Lưu thông tin người dùng vào database
  async saveUser(user: User): Promise<User> {
    // LỖI: Lưu trữ thông tin nhạy cảm mà không có thời hạn
    return await userRepository.save(user);
  }

  // LỖI: Lưu trữ thông tin nhạy cảm trong Redis mà không thiết lập thời gian hết hạn
  async cacheUserData(userId: number, userData: UserProfile): Promise<void> {
    const redisClient = Redis.createClient();
    // LỖI: Không có thời hạn (EX/PX) hoặc cơ chế tự động xóa
    await redisClient.set(`user:${userId}`, JSON.stringify(userData));
  }

  // LỖI: Lưu dữ liệu nhạy cảm trong localStorage (client-side)
  storeUserSession(user: UserProfile): void {
    // Giả lập localStorage cho môi trường server
    const localStorage = {
      setItem: (key: string, value: string) => {}
    };
    
    // LỖI: Lưu trữ thông tin nhạy cảm ở phía client mà không có thời hạn
    localStorage.setItem('userProfile', JSON.stringify(user));
  }

  // LỖI: Ghi log thông tin người dùng nhạy cảm
  logUserActivity(user: User, activity: string): void {
    // LỖI: Ghi log thông tin nhạy cảm mà không có cơ chế xoay vòng hoặc xóa tự động
    console.log(`User ${user.username} (SSN: ${user.socialSecurityNumber}) performed ${activity}`);
  }
} 