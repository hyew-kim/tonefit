package com.example.tonefitserver.domain.auth;

import com.example.tonefitserver.core.dto.auth.LoginRequest;
import com.example.tonefitserver.core.dto.auth.ReissueRequest;
import com.example.tonefitserver.core.dto.auth.SignupRequest;
import com.example.tonefitserver.core.dto.auth.TokenResponse;
import com.example.tonefitserver.core.enums.ErrorType;
import com.example.tonefitserver.core.enums.UserStatus;
import com.example.tonefitserver.core.exception.BusinessException;
import com.example.tonefitserver.core.security.JwtTokenProvider;
import com.example.tonefitserver.domain.user.RefreshToken;
import com.example.tonefitserver.domain.user.RefreshTokenRepository;
import com.example.tonefitserver.domain.user.User;
import com.example.tonefitserver.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public void signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new BusinessException(ErrorType.EMAIL_ALREADY_EXISTS);
        }

        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .status(UserStatus.ACTIVE)
                .build();

        userRepository.save(user);
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByEmailAndStatus(request.email(), UserStatus.ACTIVE)
                .orElseThrow(() -> new BusinessException(ErrorType.USER_NOT_FOUND));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BusinessException(ErrorType.INVALID_PASSWORD);
        }

        return generateAndSaveTokens(user.getEmail());
    }

    @Transactional
    public TokenResponse refresh(ReissueRequest request) {
        String refreshTokenString = request.refreshToken();

        if (!jwtTokenProvider.validateToken(refreshTokenString)) {
            throw new BusinessException(ErrorType.INVALID_TOKEN);
        }

        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenString)
                .orElseThrow(() -> new BusinessException(ErrorType.INVALID_TOKEN));

        User user = userRepository.findByEmailAndStatus(refreshToken.getEmail(), UserStatus.ACTIVE)
                .orElseThrow(() -> new BusinessException(ErrorType.USER_INACTIVE));

        return generateAndSaveTokens(user.getEmail());
    }

    private TokenResponse generateAndSaveTokens(String email) {
        String accessToken = jwtTokenProvider.createAccessToken(email);
        String refreshTokenString = jwtTokenProvider.createRefreshToken(email);

        refreshTokenRepository.findByEmail(email)
                .ifPresentOrElse(
                        rt -> rt.updateToken(refreshTokenString),
                        () -> refreshTokenRepository.save(new RefreshToken(refreshTokenString, email))
                );

        return new TokenResponse(accessToken, refreshTokenString);
    }
}
