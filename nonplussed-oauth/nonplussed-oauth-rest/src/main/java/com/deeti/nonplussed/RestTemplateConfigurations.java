package com.deeti.nonplussed;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Configuration
public class RestTemplateConfigurations {


    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
    private final ClientRegistrationRepository clientRegistrationRepository;

    public RestTemplateConfigurations(@Autowired(required = false) OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
                                      ClientRegistrationRepository clientRegistrationRepository) {
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }


    @Bean
    RestTemplate oauth2RestTemplate() {
        ClientRegistration clientRegistration = clientRegistrationRepository
                .findByRegistrationId("018efb0d-cc43-7e74-bd50-0eb3f457f224");

        RestTemplate restTemplate = new RestTemplate();

        OAuth2ClientHttpRequestInterceptor oAuth2ClientHttpRequestInterceptor = new OAuth2ClientHttpRequestInterceptor(authorizedClientManager(), clientRegistration);
        restTemplate.setInterceptors(List.of(oAuth2ClientHttpRequestInterceptor));
        return restTemplate;
    }


    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager() {
        OAuth2AuthorizedClientProvider oAuth2AuthorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, oAuth2AuthorizedClientService);
        authorizedClientManager.setAuthorizedClientProvider(oAuth2AuthorizedClientProvider);

        return authorizedClientManager;
    }

}
