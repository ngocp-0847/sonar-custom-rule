package com.example.demo.service;

import org.springframework.stereotype.Service;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;

@Service
public class TOTPService {
    
    private static final int TIME_STEP = 30; // 30 secondes
    private static final int CODE_DIGITS = 6;
    
    /**
     * Génère un TOTP (Time-based One-Time Password)
     */
    public String generateTOTP(String secretKey) {
        if (secretKey == null) {
            secretKey = generateSecretKey();
        }
        
        long timestamp = Instant.now().getEpochSecond() / TIME_STEP;
        return calculateTOTP(secretKey, timestamp);
    }
    
    /**
     * Valide un TOTP
     */
    public boolean validateTOTP(String secretKey, String inputCode) {
        if (secretKey == null || inputCode == null) {
            return false;
        }
        
        long currentTimestamp = Instant.now().getEpochSecond() / TIME_STEP;
        
        // Vérifier le code actuel et les codes adjacents (+/- 1 step) pour tenir compte des décalages d'horloges
        for (int i = -1; i <= 1; i++) {
            String expectedCode = calculateTOTP(secretKey, currentTimestamp + i);
            if (inputCode.equals(expectedCode)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Génère une clé secrète aléatoire
     */
    public String generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20]; // 160 bits
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
    
    /**
     * Calcule le code TOTP basé sur la clé secrète et le timestamp
     */
    private String calculateTOTP(String secretKey, long timestamp) {
        try {
            byte[] secret = Base64.getDecoder().decode(secretKey);
            byte[] data = longToBytes(timestamp);
            
            Mac hmac = Mac.getInstance("HmacSHA1");
            hmac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] hash = hmac.doFinal(data);
            
            // Sélection d'un octet pour déterminer l'offset
            int offset = hash[hash.length - 1] & 0x0F;
            
            // Extraction de 4 octets à partir de l'offset
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);
            
            // Génération d'un code à CODE_DIGITS chiffres
            int code = binary % (int) Math.pow(10, CODE_DIGITS);
            return String.format("%0" + CODE_DIGITS + "d", code);
            
        } catch (Exception e) {
            throw new RuntimeException("Erreur lors du calcul du TOTP", e);
        }
    }
    
    private byte[] longToBytes(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return result;
    }
}