package es.in2.issuer.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

@Builder
public record NonceResponse(
        @Schema(example = "J_8u2wAflTi2l2wQh7P_HQ", description = "The nonce generated") @JsonProperty("nonce") String nonce,
        @Schema(example = "600", description = "The nonce expiration time in seconds") @JsonProperty("nonce_expires_in") String nonceExpiresIn) {
}
