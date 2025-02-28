//package vpunko.musiceventauth.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.ProviderManager;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
//import vpunko.musiceventauth.provider.TelegramAuthenticationProvider;
//
//import java.time.Duration;
//import java.util.List;
//
//@Configuration
//public class TelegramSecurityConfig {
//
//    private final TelegramAuthenticationProvider telegramAuthenticationProvider;
//
//    public TelegramSecurityConfig(TelegramAuthenticationProvider telegramAuthenticationProvider) {
//        this.telegramAuthenticationProvider = telegramAuthenticationProvider;
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager() {
//        return new ProviderManager(List.of(telegramAuthenticationProvider));
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder()
//                .authorizationEndpoint("/oauth2/authorize")
//                .tokenEndpoint("/oauth2/token")
//                .build();
//    }
//
//    @Bean
//    public TokenSettings tokenSettings() {
//        return TokenSettings.builder()
//                .accessTokenTimeToLive(Duration.ofHours(1)) // Token valid for 1 hour
//                .build();
//    }
//
//    @Bean
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authenticationProvider(telegramAuthenticationProvider);
//    }
//}
