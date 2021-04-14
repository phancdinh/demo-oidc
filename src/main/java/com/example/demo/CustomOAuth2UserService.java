package com.example.demo;

import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.List;

public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        AuthoritiesExtractor authoritiesExtractor = new CustomAuthoritiesExtractor();
        List<GrantedAuthority> grantedAuthorityList = authoritiesExtractor.extractAuthorities(oAuth2User.getAttributes());
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(grantedAuthorityList, oAuth2User.getAttributes());
        customOAuth2User.setName(oAuth2User.getName());
        return customOAuth2User;
    }
}