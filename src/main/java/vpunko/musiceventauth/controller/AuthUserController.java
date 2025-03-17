package vpunko.musiceventauth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import vpunko.musiceventauth.service.TelegramAuthValidator;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/**
 * <a href="https://core.telegram.org/widgets/login">Telegram login widget</a>
 */
@RestController
@RequestMapping("/auth/telegram")
@RequiredArgsConstructor
public class AuthUserController {

    private final Map<Long, Boolean> authenticatedUsers = new ConcurrentHashMap<>();

    @Value("${telegram.bot_token}")
    private String tgBotToken;

    private final TelegramAuthValidator validator;

    /**
     * Return html with js scrip for an authentication
     */
    @GetMapping
    public ResponseEntity<Resource> getAuthScript() {
        Resource resource = new ClassPathResource("static/telegram.html");
        var headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=telegram.html");
        return ResponseEntity.ok().headers(headers).body(resource);
    }

    /**
     * This method is called from by js script from front
     */
    @PostMapping( consumes = MediaType.APPLICATION_JSON_VALUE)
    public String authenticate(@RequestBody Map<String, Object> telegramData) {
        Long userId = Long.parseLong(telegramData.get("id").toString());
        boolean userAuthenticated = isUserAuthenticated(userId);
        if (userAuthenticated) {
            // Отправляем сообщение в Telegram
            sendTelegramMessage(userId);

            return "valid";
        } else if (validator.isValidTelegramAuth(telegramData)) {
            // ✅ Save user as authenticated
            authenticatedUsers.put(userId, true);
            // ✅ Отправляем сообщение в Telegram
            sendTelegramMessage(userId);

            return "valid";
        }
        return "error"; // Return answer to front end widget
    }

    private void sendTelegramMessage(Long userId) {
        String url = "https://api.telegram.org/bot" + tgBotToken + "/sendMessage";

        Map<String, Object> body = Map.of(
                "chat_id", userId,
                "text", "✅ Авторизация прошла успешно! Теперь введите /next для продолжения."
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        restTemplate.postForObject(url, requestEntity, String.class);
    }


    public boolean isUserAuthenticated(Long userId) {
        return authenticatedUsers.getOrDefault(userId, false);
    }

}
