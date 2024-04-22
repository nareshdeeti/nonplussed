package com.deeti.nonplussed;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@Service
public class NonplussedService {

    private final RestTemplate oauth2RestTemplate;

    public NonplussedService(@Qualifier("oauth2RestTemplate") RestTemplate oauth2RestTemplate) {
        this.oauth2RestTemplate = oauth2RestTemplate;
    }


    public String oauthRest() {

        RequestEntity<Object> requestEntity = new RequestEntity<>(HttpMethod.GET, URI.create("http://localhost:4220/oauthRest"));

        ResponseEntity<String> exchange = oauth2RestTemplate.exchange(requestEntity, String.class);
        return exchange.getBody();
    }
}
