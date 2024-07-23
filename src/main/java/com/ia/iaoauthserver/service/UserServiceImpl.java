package com.ia.iaoauthserver.service;

import com.ia.iaoauthserver.model.UserInfo;
import com.ia.iaoauthserver.repo.UserInfoRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserInfoRepo userInfoRepo;
    @Autowired
    PasswordEncoder bCryptPasswordEncoder;

    @Override
    public Page<UserInfo> findAll(int page, int size) {
        Page<UserInfo> userList = (Page<UserInfo>) userInfoRepo.findAll(PageRequest.of(0, Integer.MAX_VALUE));
        return userList;
    }

    @Override
    public void saveUser(UserInfo userInfo) {
        bCryptPasswordEncoder.encode(userInfo.getPassword());
        userInfoRepo.save(userInfo);
    }
}
