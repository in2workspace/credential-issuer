package es.in2.issuer.infrastructure.config;

import es.in2.issuer.infrastructure.iam.util.IamAdapterFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final IamAdapterFactory iamAdapterFactory;

    @Bean
    @Profile("!dev")
    public ReactiveJwtDecoder jwtDecoder(){
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder
                .withJwkSetUri(iamAdapterFactory.getAdapter().getJwtDecoder())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        // fixme: url hardcoded
        jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("https://preproduccio-iep.dev.in2.es/cross-keycloak/realms/EAAProvider"));
        return jwtDecoder;
    }

    @Bean
    @Profile("dev")
    public ReactiveJwtDecoder jwtDecoderLocal(){
        return ReactiveJwtDecoders.fromIssuerLocation(iamAdapterFactory.getAdapter().getJwtDecoderLocal());
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web
                .ignoring()
                .requestMatchers(getSwaggerPaths())
                // fixme: parameter hardcoded
                .requestMatchers("/health");
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        // fixme: urls hardcoded
        corsConfig.setAllowedOrigins(Arrays.asList(
                "https://epu-dev-app-01.azurewebsites.net",
                "https://issueridp.dev.in2.es",
                "https://app-wallet-wda-spa-iep-dev.azurewebsites.net",
                "http://localhost:4200",
                "http://localhost:4201",
                "http://localhost:4202"));
        corsConfig.setMaxAge(8000L);
        corsConfig.setAllowedMethods(Arrays.asList(
                HttpMethod.GET.name(),
                HttpMethod.HEAD.name(),
                HttpMethod.POST.name(),
                HttpMethod.PUT.name(),
                HttpMethod.DELETE.name(),
                HttpMethod.OPTIONS.name()));
        corsConfig.setMaxAge(1800L);
        corsConfig.addAllowedHeader("*");
        corsConfig.addExposedHeader("*");
        corsConfig.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig); // Apply the configuration to all paths
        return source;
    }

    private String[] getSwaggerPaths() {
        // fixme: urls hardcoded
        return new String[]{
                "/swagger-ui/**",
                "/swagger-resources/**",
                "/api-docs/**",
                "/spring-ui/**",
                "/webjars/swagger-ui/**"
        };
    }

}