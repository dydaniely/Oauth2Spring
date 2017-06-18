package com.websystique.springmvc.security;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;



@Service
@Qualifier("liferayUserDetailService") 
public class LiferayUserDetailService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (StringUtils.isBlank(username)) {
            throw new UsernameNotFoundException("Username cannot be empty.");
        }

        try {
            List<GrantedAuthority> roles = new ArrayList<>();
            if (username.equals("test")) {
                roles.add(new SimpleGrantedAuthority("ADMIN"));
            } else if (username.equals("bill")) {
                roles.add(new SimpleGrantedAuthority("USER"));
            } else if (username.equals("bob")) {
                roles.add(new SimpleGrantedAuthority("USER"));
            }
            return new User(username, "pass", true, true, true, true, roles);

        } catch (Exception e) {
            throw new UsernameNotFoundException(String.format("Username %s not found", username));
        }
    }

}
