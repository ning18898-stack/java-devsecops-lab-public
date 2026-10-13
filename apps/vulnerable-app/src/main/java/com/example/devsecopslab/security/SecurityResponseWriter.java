package com.example.devsecopslab.security;

import java.io.IOException;
import java.util.Map;
import com.example.devsecopslab.exception.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

@Component
public class SecurityResponseWriter {
    private final JsonMapper mapper;

    public SecurityResponseWriter(JsonMapper mapper) {
        this.mapper = mapper;
    }

    public void error(HttpServletRequest request, HttpServletResponse response,
                      HttpStatus status, String message) throws IOException {
        write(response, status.value(), ApiError.of(status, message, request.getRequestURI()));
    }

    public void success(HttpServletResponse response, String message) throws IOException {
        write(response, 200, Map.of("message", message));
    }

    private void write(HttpServletResponse response, int status, Object body) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(mapper.writeValueAsString(body));
    }
}
