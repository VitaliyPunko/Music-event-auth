package vpunko.musiceventauth.provider;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class MusicEventAuthenticationProvider /*implements AuthenticationProvider*/ {

    private final PasswordEncoder passwordEncoder;
 //   private final UserDetailsServiceImpl userDetailsService;

//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        String username = authentication.getName();
//        String pwd = authentication.getCredentials().toString();
//        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//        if (passwordEncoder.matches(pwd, userDetails.getPassword())) {
//            return new UsernamePasswordAuthenticationToken(username, pwd, userDetails.getAuthorities());
//        } else {
//            throw new BadCredentialsException("Invalid password!");
//        }
//    }

 //   @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
