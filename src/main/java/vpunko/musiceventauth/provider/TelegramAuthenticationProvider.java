package vpunko.musiceventauth.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import vpunko.musiceventauth.service.TelegramAuthValidator;
import vpunko.musiceventauth.token.TelegramAuthenticationToken;

import java.util.Map;

@Component
public class TelegramAuthenticationProvider implements AuthenticationProvider {

    private final TelegramAuthValidator authValidator; // Our verification utility

    public TelegramAuthenticationProvider(TelegramAuthValidator authValidator) {
        this.authValidator = authValidator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Map<String, String> authData = (Map<String, String>) authentication.getPrincipal();

        if (authValidator.isValidTelegramAuth(authData)) {
            String userId = authData.get("id");
            String username = authData.get("username");

            // ✅ Authentication successful, return authenticated user
            return new TelegramAuthenticationToken(authData);
        } else {
            throw new AuthenticationException("Invalid Telegram authentication") {};
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(TelegramAuthenticationToken.class);
    }
}