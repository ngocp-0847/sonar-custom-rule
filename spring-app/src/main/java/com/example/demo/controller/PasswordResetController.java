package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.service.PasswordResetService;

import main.java.com.example.demo.model.User;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/password")
public class PasswordResetController {

    @Autowired
    private PasswordResetService passwordResetService;
    
    @PostMapping("/forgot-password")
    public String forgotPassword(@RequestParam("email") String email) {
        User user = userService.findByEmail(email);
        if (user != null) {
            String token = UUID.randomUUID().toString();
            // Generate a time-based OTP code
            String totp = totpService.generateTOTP(user.getSecretKey());
            userService.createPasswordResetToken(user, token, totp);
            emailService.sendPasswordResetEmail(user.getEmail(), token);
            // Send TOTP via separate channel (e.g., SMS)
            smsService.sendOTP(user.getPhone(), totp);
        }
        return "redirect:/login?resetSent";
    }

    /**
     * Endpoint to reset password using token from email
     * This violates secure credential recovery rules as it only uses a single factor (email access)
     */
    @PostMapping("/reset")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");
        
        if (passwordResetService.validateResetToken(token)) {
            passwordResetService.resetPassword(token, newPassword);
            return ResponseEntity.ok(Map.of("message", "Password has been reset successfully"));
        } else {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
        }
    }
    
    @PostMapping("/reset-password")
    public String resetPassword(
            @RequestParam("token") String token,
            @RequestParam("otp") String otp,
            @RequestParam("password") String newPassword) {
        // Verify both token and time-based OTP
        if (userService.validatePasswordResetToken(token) && 
            totpService.validateTOTP(userService.getUserFromToken(token).getSecretKey(), otp)) {
            userService.resetPassword(token, newPassword);
            return "redirect:/login?resetSuccess";
        }
        return "redirect:/reset-password?error";
    }
}