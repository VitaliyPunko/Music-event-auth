package vpunko.musiceventauth.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import vpunko.musiceventauth.service.JwtTokenService;
import vpunko.musiceventauth.service.TelegramAuthValidator;
import vpunko.musiceventauth.token.TelegramAuthenticationToken;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class TelegramAuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;

    public TelegramAuthController(AuthenticationManager authenticationManager,
                                  JwtTokenService jwtTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
    }

    @GetMapping("/token/telegram")
    public Map<String, String> getAccessToken(@RequestParam String id,
                                              @RequestParam String username,
                                              @RequestParam(name = "auth_date") long authDate,
                                              @RequestParam String hash) {

        Map<String, String> params = new HashMap<>();
        params.put("id", id);
        params.put("username", username);
        params.put("auth_date", String.valueOf(authDate));
        params.put("hash", hash);
        Authentication authentication = authenticationManager.authenticate(new TelegramAuthenticationToken(params));

        if (authentication.isAuthenticated()) {
            String accessToken = jwtTokenService.generateToken(params);
            return Map.of("access_token", accessToken, "token_type", "Bearer");
        } else {
            return Map.of("message", "Authentication failed");
        }
    }

//    @GetMapping("/token/telegram")
//    public Map<String, String> getAccessToken(@RequestParam Map<String, String> params) {
//        Authentication authentication = authenticationManager.authenticate(new TelegramAuthenticationToken(params));
//
//        if (authentication.isAuthenticated()) {
//            String accessToken = jwtTokenService.generateToken(params);
//            return Map.of("access_token", accessToken, "token_type", "Bearer");
//        } else {
//            return Map.of("message", "Authentication failed");
//        }
//    }
}
