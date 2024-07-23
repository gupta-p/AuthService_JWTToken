package com.ia.iaoauthserver.repo;

import com.ia.iaoauthserver.model.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserInfoRepo extends JpaRepository<UserInfo, Long> {
    UserInfo findByUserNameIgnoreCase(String userName);
    UserInfo findByEmailIgnoreCase(String email);
}
