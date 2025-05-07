package com.example.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;
    
    // Map pour stocker temporairement les tokens et OTPs (devrait être remplacé par une table en production)
    private java.util.Map<String, String> userTokens = new java.util.HashMap<>();
    private java.util.Map<String, User> tokenUserMap = new java.util.HashMap<>();
    
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
    
    public void createPasswordResetToken(User user, String token, String otp) {
        user.setResetToken(token);
        userRepository.save(user);
        userTokens.put(token, otp);
        tokenUserMap.put(token, user);
    }
    
    public boolean validatePasswordResetToken(String token) {
        return userTokens.containsKey(token);
    }
    
    public User getUserFromToken(String token) {
        return tokenUserMap.get(token);
    }
    
    public void resetPassword(String token, String newPassword) {
        User user = tokenUserMap.get(token);
        if (user != null) {
            user.setPassword(newPassword); // Devrait être encodé en production
            user.setResetToken(null);
            userRepository.save(user);
            // Nettoyer les maps
            userTokens.remove(token);
            tokenUserMap.remove(token);
        }
    }
}