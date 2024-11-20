package com.deeti.nonplussed.user;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

import static jakarta.persistence.GenerationType.SEQUENCE;

@Entity
@Table(name = "users")
public class Users implements UserDetails {

    private Long userId;
    private String username;
    private String email;
    private String roles;
    private String usrPassword;


    @Override
    @Transient
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String roles = getRoles();
        String[] rolesArray = roles != null ? roles.split(",") : new String[0];
        return AuthorityUtils.createAuthorityList(rolesArray);
    }

    @Override
    @Transient
    public String getPassword() {
        return usrPassword;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public void setUsrPassword(String usrPassword) {
        this.usrPassword = usrPassword;
    }

    @Id
    @GeneratedValue(strategy = SEQUENCE)
    public Long getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public String getRoles() {
        return roles;
    }

    public String getUsrPassword() {
        return usrPassword;
    }
}
