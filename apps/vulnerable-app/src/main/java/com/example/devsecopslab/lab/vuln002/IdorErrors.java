package com.example.devsecopslab.lab.vuln002;
import java.util.Map;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
@RestControllerAdvice(basePackageClasses=IdorAuthController.class)
@Order(-100)
@org.springframework.context.annotation.Profile("vuln002-local")
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(name="lab.vuln002.enabled",havingValue="true")
public class IdorErrors {
    @ExceptionHandler(IdorFailure.class) ResponseEntity<?> failure(IdorFailure error) {
        return response(error.status(),error.status()==403?"Access denied":"Article not found");
    }
    @ExceptionHandler({org.springframework.web.bind.MethodArgumentNotValidException.class,
            org.springframework.web.method.annotation.HandlerMethodValidationException.class,
            org.springframework.http.converter.HttpMessageNotReadableException.class,
            org.springframework.web.method.annotation.MethodArgumentTypeMismatchException.class})
    ResponseEntity<?> invalid(Exception error) { return response(400,"Invalid request"); }
    @ExceptionHandler(Exception.class) ResponseEntity<?> unexpected(Exception error) {
        return response(500,"Internal server error");
    }
    private ResponseEntity<?> response(int status,String message) {
        return ResponseEntity.status(status).body(Map.of("status",status,"message",message));
    }
}
