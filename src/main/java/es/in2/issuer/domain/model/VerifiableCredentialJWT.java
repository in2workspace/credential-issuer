package es.in2.issuer.domain.model;

import lombok.Builder;

@Builder
public record VerifiableCredentialJWT(String token) {
}
