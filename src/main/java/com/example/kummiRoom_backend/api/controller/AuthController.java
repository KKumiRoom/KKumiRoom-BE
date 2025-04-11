package com.example.kummiRoom_backend.api.controller;

import com.example.kummiRoom_backend.api.dto.requestDto.AuthRequestDto;
import com.example.kummiRoom_backend.api.dto.responseDto.AuthResponseDto;
import com.example.kummiRoom_backend.global.apiResult.ApiResult;
import com.example.kummiRoom_backend.global.auth.AuthService;
import com.example.kummiRoom_backend.global.auth.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;
    private final JwtService jwtService;

    //사용자 로그인
    @PostMapping("/sign-in")
    public ResponseEntity<?> login(@RequestBody AuthRequestDto request, HttpServletResponse response) throws Exception {
        AuthResponseDto authResponse = authService.login(request);

        authService.setRefreshTokenCookie(authResponse.getRefreshToken(), response);
        authService.setAccessTokenCookie(authResponse.getAccessToken(), response);

        return ResponseEntity.ok(new ApiResult(200, "success login", "로그인에 성공했습니다."));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResult> refreshToken(HttpServletRequest request,
                                                  HttpServletResponse response) {
        // 쿠키에서 리프레시 토큰을 찾기
        String refreshToken = authService.getCookieValue(request, "refreshToken");
        AuthResponseDto newTokens = authService.refreshToken(refreshToken);

        authService.setRefreshTokenCookie(newTokens.getRefreshToken(), response);
        authService.setAccessTokenCookie(newTokens.getAccessToken(), response);

        return ResponseEntity.ok(new ApiResult(200, "OK", "토큰 갱신 성공"));
    }
}
