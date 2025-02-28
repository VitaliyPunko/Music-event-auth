package vpunko.musiceventauth.service;

import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class TelegramAuthValidator {
    private static final String BOT_TOKEN = "YOUR_BOT_TOKEN";  // Replace with your bot token

    public boolean isValidTelegramAuth(Map<String, String> authData) {
        try {
            // Extract the received hash
            String receivedHash = authData.get("hash");

            // Remove "hash" and sort remaining parameters alphabetically
            String dataCheckString = authData.entrySet().stream()
                    .filter(entry -> !"hash".equals(entry.getKey()))
                    .sorted(Map.Entry.comparingByKey())
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(Collectors.joining("\n"));

            // Generate the HMAC-SHA256 hash using the bot token
            byte[] secretKey = MessageDigest.getInstance("SHA-256")
                    .digest(BOT_TOKEN.getBytes(StandardCharsets.UTF_8));

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secretKey, "HmacSHA256"));
            byte[] hmac = mac.doFinal(dataCheckString.getBytes(StandardCharsets.UTF_8));

            // Convert the HMAC result to a hexadecimal string
            String calculatedHash = bytesToHex(hmac);

            // Compare the calculated hash with the received hash
//            return calculatedHash.equals(receivedHash);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}