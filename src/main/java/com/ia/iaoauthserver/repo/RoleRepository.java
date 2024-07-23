package com.ia.iaoauthserver.repo;

import com.ia.iaoauthserver.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, String> {
	Role findByName(String roleName);
}
