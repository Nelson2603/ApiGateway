package org.example.apigateway.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Фильтр, который вытаскивает логин из JWT и кладёт его в заголовок X-User-Login.
 *
 * Запускается ПОСЛЕ Security (у @Order(1) — высокий приоритет у SecurityFilterChain).
 * Если пользователь не аутентифицирован — просто пропускает запрос дальше,
 * и запрос отклонит Security позже.
 */
@Slf4j
@Component
@Order(2)                                  // после Security цепочки (у неё порядок 1)
public class UserLoginFilter extends OncePerRequestFilter {

    public static final String USER_LOGIN_HEADER = "X-User-Login";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Если пользователь не аутентифицирован — пропускаем дальше без изменений
        if (auth == null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof Jwt jwt)) {
            filterChain.doFilter(request, response);
            return;
        }

        String login = jwt.getClaimAsString("preferred_username");
        if (login == null || login.isBlank()) {
            log.warn("JWT не содержит preferred_username, X-User-Login не будет добавлен");
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("Добавляем заголовок {}: {}", USER_LOGIN_HEADER, login);

        // Оборачиваем запрос и передаём дальше
        filterChain.doFilter(new UserLoginRequestWrapper(request, login), response);
    }

    /**
     * Применяем фильтр только к API-запросам.
     * Actuator, health-check и т.п. не должны его проходить.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }
}