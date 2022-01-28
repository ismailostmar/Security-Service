package org.sid.SecurityService.Sec.Filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.catalina.filters.ExpiresFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationToken = request.getHeader("Authorization");
        if (authorizationToken != null && authorizationToken.startsWith("Bearer ")) {
            try {
                // Teste de requete et Verification
                String jwt = authorizationToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("mySecret1234");

                // Verification
                JWTVerifier jwtVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT =jwtVerifier.verify(jwt);

                String username = decodedJWT.getSubject();
                String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                Collection<GrantedAuthority> authorities = new ArrayList<>();

                for(String r:roles){
                    authorities.add(new SimpleGrantedAuthority(r));
                }

                // Pour Athentifier l'utilisateur
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(username,null,authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                // Apres Authentification
                filterChain.doFilter(request,response);
            }
            catch (Exception e){
                response.setHeader("error-message",e.getMessage());
                // Si le Token est expiré , Alors l'user n'as pas le droit
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        }
        else{
            filterChain.doFilter(request,response);
        }

    }
}
