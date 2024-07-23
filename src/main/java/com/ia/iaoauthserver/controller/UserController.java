package com.ia.iaoauthserver.controller;

import com.ia.iaoauthserver.model.UserInfo;
import com.ia.iaoauthserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    UserService userService;

   // @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    @RequestMapping(value = "/api/users", method = RequestMethod.GET)
    public Page<UserInfo> findByUserByEmail(@RequestParam int page, @RequestParam int size) {
        Page<UserInfo> userInfo = userService.findAll(page, size);
        return userInfo;
    }
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN') or hasAuthority('SCOPE_ROLE_TEACHER') or hasAuthority('SCOPE_ROLE_STUDENT')" )
    @RequestMapping(value = "/api/users/add", method = RequestMethod.POST)
    public void insertUser(@RequestBody UserInfo userInfo) {
        userService.saveUser(userInfo);
    }

}

