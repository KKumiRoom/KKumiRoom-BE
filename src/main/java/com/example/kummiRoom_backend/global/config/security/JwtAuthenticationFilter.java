package com.example.kummiRoom_backend.global.config.security;

import com.example.kummiRoom_backend.global.apiResult.ApiResult;
import com.example.kummiRoom_backend.global.auth.AuthService;
import com.example.kummiRoom_backend.global.auth.JwtService;
import com.example.kummiRoom_backend.global.exception.UnauthorizedException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	private final JwtService jwtService;
	private final AuthService authService;

	//todo 서비스 경로 고려
	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		String path = request.getRequestURI();

		return path.startsWith("/api/openapi") ||
			path.startsWith("/v3/api-docs") ||
			path.startsWith("/swagger-resources") ||
			path.startsWith("/webjars/") ||
			path.equals("/");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		// 쿠키에서 accessToken을 추출
		String accessToken = authService.getCookieValue(request, "accessToken");

		// 토큰이 없으면 필터 체인으로 넘어감
		if (accessToken == null || accessToken.isEmpty()) {
			filterChain.doFilter(request, response);
			return;
		}

		try {

			// JWT 유효성 검사
			final String userId = jwtService.extractAuthId(accessToken);
			System.out.println(userId);

			if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				if (jwtService.isValidToken(accessToken)) {
					List<SimpleGrantedAuthority> authorities =
						Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

					UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
						userId,
						null,
						authorities
					);

					authToken.setDetails(
						new WebAuthenticationDetailsSource().buildDetails(request)
					);

					SecurityContextHolder.getContext().setAuthentication(authToken);
				} else {
					throw new BadCredentialsException("Invalid token");
				}
			}
		} catch (ExpiredJwtException e) {
			throw new UnauthorizedException("Token is expired");
		} catch (Exception e) {
			throw new UnauthorizedException("Token validation failed");
		}
		filterChain.doFilter(request, response);
	}
}
