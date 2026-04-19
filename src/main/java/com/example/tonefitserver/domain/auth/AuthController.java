package com.example.tonefitserver.domain.auth;

import com.example.tonefitserver.core.dto.ApiResponse;
import com.example.tonefitserver.core.dto.auth.LoginRequest;
import com.example.tonefitserver.core.dto.auth.ReissueRequest;
import com.example.tonefitserver.core.dto.auth.SignupRequest;
import com.example.tonefitserver.core.dto.auth.TokenResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ApiResponse<Void> signup(@RequestBody @Valid SignupRequest request) {
        authService.signup(request);
        return ApiResponse.success(null);
    }

    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(@RequestBody @Valid LoginRequest request) {
        return ApiResponse.success(authService.login(request));
    }

    @PostMapping("/refresh")
    public ApiResponse<TokenResponse> refresh(@RequestBody @Valid ReissueRequest request) {
        return ApiResponse.success(authService.refresh(request));
    }
}
