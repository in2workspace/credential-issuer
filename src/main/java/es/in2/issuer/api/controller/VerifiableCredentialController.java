package es.in2.issuer.api.controller;

import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.api.config.SwaggerConfig;
import es.in2.issuer.api.model.dto.*;
import es.in2.issuer.api.exception.InvalidTokenException;
import es.in2.issuer.api.service.VerifiableCredentialService;
import es.in2.issuer.api.util.Utils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.text.ParseException;

@RestController
@RequestMapping("/api/vc")
@RequiredArgsConstructor
@Slf4j
public class VerifiableCredentialController {

    private final VerifiableCredentialService verifiableCredentialService;

    @Operation(
            summary = "Generate a new Verifiable Credential",
            description = "Generate a new Verifiable Credential and returns it with its id (nonce) assigned, lifetime in seconds and format",
            tags = {SwaggerConfig.TAG_PRIVATE}
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "201",
                            description = "Returns an URL with a linked ID parameter to retrieve the created Verifiable Credential."
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "Credential Request did not contain a proof, proof was invalid or no grants retrieved for the given user",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = CredentialResponseError.class),
                                    examples = @ExampleObject(name = "invalidOrMissingProof", value = "{\"error\": \"invalid_or_missing_proof\", \"description\": \"Credential Request did not contain a proof, or proof was invalid\"}"))
                    ),
                    @ApiResponse(
                            responseCode = "500",
                            description = "This response is returned when an unexpected server error occurs. It includes an error message if one is available.",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = GenericResponseError.class))
                    )
            }
    )
    @PostMapping(value = "/type", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    //public Mono<VerifiableCredentialResponseDTO> createVerifiableCredential(
    public VerifiableCredentialDTO createVerifiableCredential(
            @RequestBody CredentialRequestDTO credentialRequest,
            ServerWebExchange exchange
    ) throws InvalidTokenException, ParseException {
        /*
        return Mono.defer(() -> {
                    try {
                        SignedJWT token = Utils.getToken(exchange);
                        String username = token.getJWTClaimsSet().getClaim("preferred_username").toString();

                        return verifiableCredentialService.generateVerifiableCredentialResponse(username, credentialRequest, token.getParsedString());
                    } catch (InvalidTokenException | ParseException e) {
                        return Mono.error(e);
                    }
                }).doOnNext(result -> log.info("VerifiableCredentialController - createVerifiableCredential()"))
                .onErrorMap(e -> new RuntimeException("Error processing the request", e));
         */
        SignedJWT token = Utils.getToken(exchange);
        String username = token.getJWTClaimsSet().getClaim("preferred_username").toString();
        VerifiableCredentialResponseDTO verifiableCredentialResponseDTO = verifiableCredentialService.generateVerifiableCredentialResponse(username, credentialRequest, token.getParsedString()).block();

        return verifiableCredentialResponseDTO.getCredentials().get(0);
    }


    @Operation(summary = "Retrieve a Verifiable Credential with its ID", tags = {SwaggerConfig.TAG_PRIVATE})
    @Parameter(
            name = "id",
            description = "The ID of the verifiable credential to retrieve",
            required = true,
            in = ParameterIn.PATH,
            schema = @Schema(type = "string")
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Returns the Verifiable Credential in the location response header if exists in the memory cache and match with the ID presented."
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "The given credential ID does not match with any verifiable credentials",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = CredentialResponseError.class),
                                    examples = @ExampleObject(name = "vcDoesNotExist", value = "{\"error\": \"vc_does_not_exist\", \"description\": \"Credential with id: 'edFrxZZ' does not exist.\"}"))
                    ),
                    @ApiResponse(
                            responseCode = "500",
                            description = "This response is returned when an unexpected server error occurs. It includes an error message if one is available.",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = GenericResponseError.class))
                    )
            }
    )
    @GetMapping("/id/{credentialId}")
    @ResponseStatus(HttpStatus.OK)
    public Mono<Void> getVerifiableCredential(
            @PathVariable("credentialId") String credentialId,
            ServerWebExchange exchange
    ) {
        log.info("VerifiableCredentialController - getVerifiableCredential()");

        return verifiableCredentialService.getVerifiableCredential(credentialId)
                .doOnSuccess(result -> exchange.getResponse().getHeaders().set(HttpHeaders.LOCATION, result))
                .then();
    }

}
