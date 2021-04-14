package com.example.demo;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UserController {
    private final OAuth2AuthorizedClientService authorizedClientService;

    public UserController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping({"", "/","/hello"})
    public String hello(Model model, @RequestParam(value = "name", required = false, defaultValue = "World") String name) {
        model.addAttribute("name", name);
        return "hello";
    }

    @GetMapping("/user")
    public String user(Model model, Authentication authentication2, @AuthenticationPrincipal OidcUser principal) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken)
                securityContext.getAuthentication();


        OAuth2AuthorizedClient client = authorizedClientService
                .loadAuthorizedClient(oauth2Token.getAuthorizedClientRegistrationId(),
                        oauth2Token.getName());
        authentication2.getAuthorities();
        if (client == null || client.getAccessToken() == null) {
            System.out.println("null");
            SecurityContextHolder.clearContext();
            return "redirect:/login";
        } else {
            model.addAttribute("access_token", client.getAccessToken().getTokenValue());
            model.addAttribute("getPrincipal", oauth2Token.getPrincipal());
            model.addAttribute("groups", oauth2Token.getPrincipal().getAttribute("groups"));
            String idToken = principal.getIdToken().getTokenValue();
            String logOutRedirect = "http://htid.com/perform_logout";
            String logout = String.format("https://localhost:9443/oidc/logout?id_token_hint=%1$s&post_logout_redirect_uri=%2$s", idToken, logOutRedirect);
            model.addAttribute("logoutUrl", logout);
        }
        return "user/index";
    }

    @GetMapping("/admin/index")
    public String admin(Model model, @RequestParam(value = "name", required = false, defaultValue = "World") String name) {
        model.addAttribute("name", name);
        return "admin";
    }
    @GetMapping("/custom_logout")
    public String customLogoutCheck(Model model, @RequestParam(value = "name", required = false, defaultValue = "World") String name) {
        model.addAttribute("name", name);
        return "admin";
    }
    @PostMapping("/custom_logout")
    public String customLogoutCheckPost(Model model, @RequestParam(value = "name", required = false, defaultValue = "World") String name) {
        model.addAttribute("name", name);
        return "admin";
    }
}