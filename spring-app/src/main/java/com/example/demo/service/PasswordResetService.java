package com.example.demo.service;

import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;

@Service
public class PasswordResetService {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private EmailService emailService;
    
    /**
     * Insecure password reset method that only sends an email 
     * with a reset link without additional verification factors
     */
    public void forgotPassword(String email) {
        User user = userRepository.findByEmail(email);
        
        if (user != null) {
            // Generate simple random token
            String token = UUID.randomUUID().toString();
            user.setResetToken(token);
            userRepository.save(user);
            
            // Send email with reset link
            String resetUrl = "http://localhost:8080/reset-password?token=" + token;
            emailService.sendPasswordResetEmail(user.getEmail(), resetUrl);
        }
    }
    
    /**
     * Insecure password reset validation that only checks the token
     * without any additional security factors
     */
    public boolean validateResetToken(String token) {
        return userRepository.findByResetToken(token) != null;
    }
    
    /**
     * Insecure method that resets password using only a token
     * without additional verification
     */
    public void resetPassword(String token, String newPassword) {
        User user = userRepository.findByResetToken(token);
        
        if (user != null) {
            user.setPassword(newPassword); // Should be encoded in real app
            user.setResetToken(null);
            userRepository.save(user);
        }
    }
    
    /**
     * Another insecure reset method using security questions
     * which are considered weak verification methods
     */
    public boolean resetPasswordWithSecurityQuestion(String email, String answer, String newPassword) {
        User user = userRepository.findByEmail(email);
        
        if (user != null && user.getSecurityAnswer().equals(answer)) {
            user.setPassword(newPassword); // Should be encoded in real app
            userRepository.save(user);
            return true;
        }
        
        return false;
    }
}