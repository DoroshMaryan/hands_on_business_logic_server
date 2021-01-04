package com.epam.dorosh.businesslogic.authentication.proxy;

import com.epam.dorosh.businesslogic.authentication.data.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class AuthenticationServerProxy {
    @Autowired
    private RestTemplate restTemplate;

    @Value("${auth.server.base.url}")
    private String baseUrl;

    public void sendAuth(final String username, final String password) {
        final String url = baseUrl + "/user/auth";
        var body = new User();
        body.setUsername(username);
        body.setPassword(password);

        final var request = new HttpEntity<>(body);
        restTemplate.postForEntity(url, request, Void.class);
    }

    public boolean sendOtp(final String username, final String code) {
        final String url = baseUrl + "/otp/check";
        var body = new User();
        body.setUsername(username);
        body.setCode(code);

        final var request = new HttpEntity<>(body);
        final var respond = restTemplate.postForEntity(url, request, Void.class);

        return respond.getStatusCode().equals(HttpStatus.OK);
    }
}
