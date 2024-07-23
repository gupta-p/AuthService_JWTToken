package com.ia.iaoauthserver.service;

import com.ia.iaoauthserver.model.UserInfo;
import org.springframework.data.domain.Page;

public interface UserService {
    Page<UserInfo> findAll(int page, int size);

    void saveUser(UserInfo userInfo);
}
