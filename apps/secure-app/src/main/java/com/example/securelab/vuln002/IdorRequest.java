package com.example.securelab.vuln002;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.AssertTrue;
import com.fasterxml.jackson.annotation.JsonIgnore;
public record IdorRequest(@NotBlank @Size(max=200) String title,
        @NotBlank @Size(max=20000) String content) {
    @AssertTrue @JsonIgnore
    public boolean isContentWithinUtf8Limit() {
        return content == null || content.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 60000;
    }
}
