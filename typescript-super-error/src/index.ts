class Animal {
    constructor(name: string) {
      console.log(`Animal constructor called with name: ${name}`);
    }
  
    doSomething(): void {
      console.log('Animal doing something');
    }
  }
  
  // Lớp con kế thừa từ Animal với lỗi gọi super() nhiều lần
  class Dog extends Animal {
    name: string;
    
    constructor(name: string) {
      super(name); // Gọi super() đúng cách
      this.name = name; 
      super(name); // Noncompliant: super() được gọi lần thứ hai
      super.doSomething();
    }
  
    bark(): void {
      console.log(`${this.name} is barking!`);
    }
  }
  
  // Sửa lỗi: Phiên bản đúng
  class GoodDog extends Animal {
    name: string;
    
    constructor(name: string) {
      super(name); // Chỉ gọi super() một lần
      this.name = name;
      super.doSomething();
    }
  
    bark(): void {
      console.log(`${this.name} is barking!`);
    }
  }
  
  // Test
  try {
    const dog = new Dog('Rex');
    dog.bark();
  } catch (error) {
    console.error('Error creating Dog:', error);
  }
  
  const goodDog = new GoodDog('Buddy');
  goodDog.bark(); 

// Thêm ví dụ về Mass Parameter Assignment
console.log('\n\n==========================================');
console.log('CHẠY VÍ DỤ VỀ MASS PARAMETER ASSIGNMENT');
console.log('==========================================');
import './massParmAssignment';

// Thêm ví dụ về XXE Vulnerability
console.log('\n\n==========================================');
console.log('CHẠY VÍ DỤ VỀ XXE VULNERABILITY');
console.log('==========================================');
import './xxeVulnerability'; 

// Thêm ví dụ về Cache Sensitive Data Vulnerability
console.log('\n\n==========================================');
console.log('CHẠY VÍ DỤ VỀ CACHE SENSITIVE DATA VULNERABILITY');
console.log('==========================================');
import './cacheVulnerability'; 