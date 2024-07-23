package com.ia.iaoauthserver.service;

import com.ia.iaoauthserver.model.Role;
import com.ia.iaoauthserver.model.UserInfo;
import com.ia.iaoauthserver.repo.RoleRepository;
import com.ia.iaoauthserver.repo.UserInfoRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserInfoRepo userRepository;
    @Autowired
    RoleRepository roleRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo user = userRepository.findByUserNameIgnoreCase(username);
        if (user == null) {
            user = userRepository.findByEmailIgnoreCase(username);
        }
        List<String> roles = new ArrayList<>();
        roles.add(user.getRole().getName().toString());

        Collection<GrantedAuthority> authorities = roles
                .stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());

        for (String rolesString : roles) {
            Role role = roleRepository.findByName(rolesString);
            if (role != null && role.getPrivileges() != null && !role.getPrivileges().isEmpty()) {
                authorities.addAll(role.getPrivileges().stream().map(p -> new SimpleGrantedAuthority(p))
                        .collect(Collectors.toSet()));

            }
           /* if (user.getPrivileges() != null) {
                authorities.addAll(user.getPrivileges().stream().map(p -> new SimpleGrantedAuthority(p))
                        .collect(Collectors.toSet()));
            }*/
        }

        return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassword(), user.isActive() && !user.isDeleted(), true, true, true, authorities);
    }
}

