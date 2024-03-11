package es.in2.issuer.api.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@Schema(description = """
    Implements the credential response according to 
    https://github.com/hesusruiz/EUDIMVP/blob/main/issuance.md#credential-response
    """)
public class VerifiableCredentialResponseDTO {

    @Schema(
            example = "jwt_vc_json",
            description = "Format of the issued Credential."
    )
    @JsonProperty("format")
    private final String format;

    @Schema(
            example = "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
            description = "Contains issued Credential"
    )
    @JsonProperty("credential")
    private final String credential;

    @Schema(
            example = "fGFF7UkhLA",
            description = """
            Nonce to be used to create a proof of possession of key material when requesting a Credential. 
            When received, the Wallet MUST use this nonce value for its subsequent credential requests until the 
            Credential Issuer provides a fresh nonce.
        """
    )
    @JsonProperty("c_nonce")
    private final String cNonce;

    @Schema(
            example = "35fd",
            description = "Lifetime in seconds of the c_nonce"
    )
    @JsonProperty("c_nonce_expires_in")
    private final int cNonceExpiresIn;
}
