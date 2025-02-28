package vpunko.musiceventauth.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import vpunko.musiceventauth.entity.User;

import java.util.Collection;
import java.util.List;

public class SpotifyUserDetails implements UserDetails {

    private final User user;

    public SpotifyUserDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }
}
