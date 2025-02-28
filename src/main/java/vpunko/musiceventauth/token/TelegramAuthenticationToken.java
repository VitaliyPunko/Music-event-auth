package vpunko.musiceventauth.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Map;

public class TelegramAuthenticationToken extends AbstractAuthenticationToken {

    private final Map<String, String> telegramData;

    public TelegramAuthenticationToken(Map<String, String> telegramData) {
        super(null);
        this.telegramData = telegramData;
        setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return telegramData;
    }

    @Override
    public Object getCredentials() {
        return null; // No password needed
    }
}