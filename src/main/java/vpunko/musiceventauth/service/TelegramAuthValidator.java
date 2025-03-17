package vpunko.musiceventauth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * <a href="https://core.telegram.org/widgets/login#checking-authorization">Checking authorization</a>
 * check if user hash is equal to get hash from user data
 */
@Slf4j
@Component
public class TelegramAuthValidator {

    public static final String HMAC_SHA_256 = "HmacSHA256";
    public static final String HASH = "hash";

    private final String botToken;

    public TelegramAuthValidator(@Value("${telegram.bot_token}") String botToken) {
        this.botToken = botToken;
    }


    public boolean isValidTelegramAuth(Map<String, Object> authData) {
        try {
            String receivedHash = (String) authData.get(HASH);

            // Remove "hash" and sort remaining parameters alphabetically
            String dataCheckString = authData.entrySet().stream()
                    .filter(entry -> !HASH.equals(entry.getKey()))
                    .sorted(Map.Entry.comparingByKey())
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(Collectors.joining("\n"));

            // Generate the HMAC-SHA256 hash using the bot token
            byte[] secretKey = MessageDigest.getInstance("SHA-256")
                    .digest(botToken.getBytes(StandardCharsets.UTF_8));

            Mac mac = Mac.getInstance(HMAC_SHA_256);
            mac.init(new SecretKeySpec(secretKey, HMAC_SHA_256));
            byte[] hmac = mac.doFinal(dataCheckString.getBytes(StandardCharsets.UTF_8));

            // Convert the HMAC result to a hexadecimal string
            String calculatedHash = bytesToHex(hmac);
            return calculatedHash.equals(receivedHash);
        } catch (Exception e) {
            log.error("Error occurred during telegram token validation: {}", e.getMessage());
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