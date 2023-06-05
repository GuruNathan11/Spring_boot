package com.mettler.jwt.mettlerAuth.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.mettler.jwt.mettlerAuth.Models.User;

public interface UserRepository extends MongoRepository<User, Long> {
	 
    Optional<User> findByUsername(String username);
  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
User findByEmail(String email);
}