package com.example.zerotrustframework.authentication;

import com.example.zerotrustframework.common.User;
import com.example.zerotrustframework.common.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AuthenticationFilter extends OncePerRequestFilter {

    private final TokenValidator tokenValidator;
    private final UserService userService;

    public AuthenticationFilter(TokenValidator tokenValidator, UserService userService){
        this.tokenValidator=tokenValidator;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader=request.getHeader("Authorization");
        if(authHeader!=null||authHeader.startsWith("Bearer ")){
            String token=authHeader.substring(7);
            String userName=tokenValidator.extractUsername(token);
            if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                User user = userService.LoadUserByUsername(userName);
                if (tokenValidator.isValid(token, user)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            /*if(!tokenValidator.isValid(token)){
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            Authentication authentication=tokenValidator.buildAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);*/
        }



        filterChain.doFilter(request,response);
    }
}
