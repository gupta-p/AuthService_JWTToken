package com.ia.iaoauthserver.repo;


import com.ia.iaoauthserver.model.Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, String> {
    Client findByClientId(String clientId);
    void deleteByClientId(String clienId);
}
