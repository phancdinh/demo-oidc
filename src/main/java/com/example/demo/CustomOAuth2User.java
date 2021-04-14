package com.example.demo;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {
    private List<GrantedAuthority> authorities;
    private Map<String, Object> attributes;
    private String name;


    public CustomOAuth2User(List<GrantedAuthority> authorities, Map<String, Object> attributes) {
        this.authorities = authorities;
        this.attributes = attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
        if (this.attributes == null) {
            this.attributes = new HashMap<>();
            this.attributes.put("name", this.getName());
        }
        return attributes;
    }

    @Override
    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

}