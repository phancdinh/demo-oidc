package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.function.Consumer;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    final CustomLogoutSuccessHandler customizeLogoutSuccessHandler;
//
//    public SecurityConfig(CustomLogoutSuccessHandler customizeLogoutSuccessHandler) {
//        this.customizeLogoutSuccessHandler = customizeLogoutSuccessHandler;
//    }

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/admin/**").access("hasRole('USER')")
                .anyRequest().authenticated()
                .and()
                .oauth2Login(oauth2 -> oauth2
                                .authorizationEndpoint(authorization -> authorization
                                        .authorizationRequestResolver(
                                                authorizationRequestResolver(this.clientRegistrationRepository)
                                        )))
                .logout()
                .logoutUrl("/perform_logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/perform_logout"))
                .logoutSuccessUrl("/login")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID");
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//                .logoutSuccessHandler(customizeL ogoutSuccessHandler)
//                .logoutSuccessUrl("/login")
//                .invalidateHttpSession(true)        // set invalidation state when logout
//                .deleteCookies("JSESSIONID");

        http.exceptionHandling().accessDeniedPage("/403");
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(
                authorizationRequestCustomizer());

        return  authorizationRequestResolver;
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        String locale = LocaleContextHolder.getLocale().getLanguage();
        return customizer -> customizer
                .additionalParameters(params -> {
                    params.put("lang", locale);
//                    params.put("authFailure", true);
//                    params.put("authFailureMsg", "account.confirmation.pending");
                });
    }
}
