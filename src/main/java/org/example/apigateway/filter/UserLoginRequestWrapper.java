package org.example.apigateway.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.*;


public class UserLoginRequestWrapper extends HttpServletRequestWrapper {

    private final String login;

    public UserLoginRequestWrapper(HttpServletRequest request, String login) {
        super(request);
        this.login = login;
    }

    @Override
    public String getHeader(String name) {
        if ("X-User-Login".equalsIgnoreCase(name)) {
            return login;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if ("X-User-Login".equalsIgnoreCase(name)) {
            return Collections.enumeration(List.of(login));
        }
        return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        Set<String> names = new LinkedHashSet<>();
        Enumeration<String> original = super.getHeaderNames();
        while (original.hasMoreElements()) {
            names.add(original.nextElement());
        }
        names.add("X-User-Login");
        return Collections.enumeration(names);
    }
}