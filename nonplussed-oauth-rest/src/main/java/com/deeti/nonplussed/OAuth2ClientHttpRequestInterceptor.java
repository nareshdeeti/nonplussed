package com.deeti.nonplussed;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.io.IOException;
import java.nio.charset.Charset;

public class OAuth2ClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private final OAuth2AuthorizedClientManager ouOAuth2AuthorizedClientManager;
    private final ClientRegistration clientRegistration;

    public OAuth2ClientHttpRequestInterceptor(OAuth2AuthorizedClientManager ouOAuth2AuthorizedClientManager,
                                              ClientRegistration clientRegistration) {
        this.ouOAuth2AuthorizedClientManager = ouOAuth2AuthorizedClientManager;
        this.clientRegistration = clientRegistration;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {

        String clientId = "nonplussed";
        String clientSecret = "nonplussed";

        HttpHeaders headers = request.getHeaders();

        OAuth2AuthorizeRequest oAuth2AuthorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("018efb0d-cc43-7e74-bd50-0eb3f457f224")
                .principal("nonplussed")
                .build();

        OAuth2AuthorizedClient authorize = ouOAuth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
        assert authorize != null;
        OAuth2AccessToken accessToken = authorize.getAccessToken();

        headers.setBearerAuth(accessToken.getTokenValue());
        return execution.execute(request, body);
    }

}
