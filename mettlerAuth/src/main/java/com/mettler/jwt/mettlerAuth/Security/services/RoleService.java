package com.mettler.jwt.mettlerAuth.Security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mettler.jwt.mettlerAuth.Models.Role;
import com.mettler.jwt.mettlerAuth.repository.RoleRepository;

@Service
public class RoleService {

    @Autowired
    private RoleRepository roleDao;

    public Role createNewRole(Role role) {
        return roleDao.save(role);
    }
}