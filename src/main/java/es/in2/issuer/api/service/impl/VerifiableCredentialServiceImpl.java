package es.in2.issuer.api.service.impl;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.upokecenter.cbor.CBORObject;
import es.in2.issuer.api.config.AppConfiguration;
import es.in2.issuer.api.model.dto.*;
import es.in2.issuer.api.model.enums.SignatureType;
import es.in2.issuer.api.exception.*;
import es.in2.issuer.api.repository.CacheStore;
import es.in2.issuer.api.service.AuthenticSourcesRemoteService;
import es.in2.issuer.vault.AzureKeyVaultService;
import es.in2.issuer.api.service.RemoteSignatureService;
import es.in2.issuer.api.service.VerifiableCredentialService;
import es.in2.issuer.api.util.Utils;
import id.walt.crypto.KeyAlgorithm;
import id.walt.crypto.KeyId;
import id.walt.model.DidMethod;
import id.walt.servicematrix.ServiceMatrix;
import id.walt.services.did.DidService;
import id.walt.services.key.KeyService;
import id.walt.signatory.Ecosystem;
import id.walt.signatory.ProofConfig;
import id.walt.signatory.ProofType;
import id.walt.signatory.Signatory;
import id.walt.signatory.dataproviders.MergingDataProvider;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.minvws.encoding.Base45;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static es.in2.issuer.api.util.Constants.CREDENTIAL_SUBJECT;
import static es.in2.issuer.api.util.Constants.LEAR_CREDENTIAL;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerifiableCredentialServiceImpl implements VerifiableCredentialService {

    private final AzureKeyVaultService azureKeyVaultService;
    private final RemoteSignatureService remoteSignatureService;
    private final AuthenticSourcesRemoteService authenticSourcesRemoteService;
    private final CacheStore<VerifiableCredentialJWT> credentialCacheStore;
    private final CacheStore<String> cacheStore;
    private final AppConfiguration appConfiguration;

    private String didElsi;
    @PostConstruct
    private void initializeAzureProperties() {
        didElsi = appConfiguration.getIssuerDid();
    }

    @Override
    public Mono<VerifiableCredentialResponseDTO> generateVerifiableCredentialResponse(
            String username,
            CredentialRequestDTO credentialRequestDTO,
            String token
    ) {
        return getNonceClaim(credentialRequestDTO.getProof().getJwt())
                .flatMap(nonceClaim -> checkIfCacheExistsById(nonceClaim)
                        .flatMap(verifyToken -> verifyIfUserAccessTokenIsAssociatedWithNonceOnCache(token, verifyToken)
                                .then(Mono.fromRunnable(() -> cacheStore.delete(nonceClaim)))
                                .thenReturn(nonceClaim)))
                .flatMap(nonceClaim -> extractDidFromJwtProof(credentialRequestDTO.getProof().getJwt())
                        .flatMap(subjectDid -> {
                            String format = credentialRequestDTO.getFormat();
                            Mono<VerifiableCredentialResponseDTO> credentialMono;

                            if ("jwt_vc".equals(format)) {
                                credentialMono = generateVerifiableCredential(username, token, LEAR_CREDENTIAL, nonceClaim)
                                        .map(credential -> new VerifiableCredentialResponseDTO(format, credential, nonceClaim, 600));
                            } else if ("cwt_vc".equals(format)) {
                                credentialMono = generateVerifiableCredentialInCWTFormat(username, token, LEAR_CREDENTIAL, subjectDid)
                                        .map(credential -> new VerifiableCredentialResponseDTO(format, credential, nonceClaim, 600));
                            } else {
                                return Mono.error(new IllegalArgumentException("Unsupported credential format: " + format));
                            }

                            return storeTokenInCache(token)
                                    .flatMap(cNonce -> storeCredentialResponseInMemoryCache(cNonce, String.valueOf(credentialMono))
                                            .then(Mono.just(cNonce))
                                            .flatMap(savedCNonce -> credentialMono));
                        }));
    }



    private Mono<String> generateVerifiableCredential(
            String username,
            String token,
            String credentialType,
            String subjectDid
    ){
        return Mono.defer(() -> {
            //try {
                // Load walt.id SSI-Kit services from "$workingDirectory/service-matrix.properties"
                new ServiceMatrix("service-matrix.properties");

                // Define used services
                Signatory signatory = Signatory.Companion.getService();
                KeyService keyService = KeyService.Companion.getService();

                // generate key pairs for issuer
                KeyId issuerKey = keyService.generate(KeyAlgorithm.ECDSA_Secp256k1);
                String issuerDid = DidService.INSTANCE.create(DidMethod.key, issuerKey.getId(),null);
                Instant expiration = Instant.now().plus(30, ChronoUnit.DAYS);

                // Prepare desired custom data that should replace the default template data
                log.info("Fetching information from authentic sources ...");
                //return authenticSourcesRemoteService.getUser(token)
                return authenticSourcesRemoteService.getUserFromLocalFile()
                        .flatMap(appUser -> {
                            log.info("Getting credential subject data for credentialType: " + credentialType + " ...");
                            Map<String, Map<String, String>> credentialSubject = appUser.getCredentialSubjectData();

                            Map<String, String> credentialSubjectData;

                            if (!credentialSubject.isEmpty()) {
                                credentialSubjectData = credentialSubject.getOrDefault(credentialType, null);
                            } else {
                                return Mono.error(new NoSuchElementException("No data saved for CredentialType " + credentialType + " and username " + username + "."));
                            }

                            Map<String, Object> data = Map.of(CREDENTIAL_SUBJECT, credentialSubjectData);

                            // Create the VC in jwt format.
                            String jwtVC = signatory.issue(
                                    credentialType,
                                    new ProofConfig(issuerDid, subjectDid,null,null, ProofType.JWT,null,null,null,null,null,null, expiration,null,null,null, Ecosystem.DEFAULT,null,"",null,null),
                                    new MergingDataProvider(data),
                                    null,
                                    false
                            );

                            Payload vcPayload;
                            try {
                                vcPayload = JOSEObject.parse(jwtVC).getPayload();
                            } catch (ParseException e) {
                                log.error("ParseException {}", e.getMessage());
                                return Mono.error(new RuntimeException(e));
                            }
                            String vcString = setIssuerDid(vcPayload).toString();

                            log.info(vcString);

                            log.info("Signing credential in JADES remotely ...");
                            SignatureRequest signatureRequest = new SignatureRequest(
                                    new SignatureConfiguration(SignatureType.JADES, Collections.emptyMap()),
                                    vcString
                            );


                            return remoteSignatureService.sign(signatureRequest, token)
                                    .publishOn(Schedulers.boundedElastic())
                                    //.doOnSuccess(signedData -> commitCredentialSourceData(vcPayload, token).subscribe())
                                    .map(SignedData::getData);


                        });
            //} catch (UserDoesNotExistException e) {
            //    log.error("UserDoesNotExistException {}", e.getMessage());
            //    return Mono.error(new RuntimeException(e));
            //}
        });
    }

    private Mono<String> generateVerifiableCredentialInCWTFormat(
            String username,
            String token,
            String credentialType,
            String subjectDid
    ) {
        return Mono.defer(() -> {
            //try {
                // Load walt.id SSI-Kit services from "$workingDirectory/service-matrix.properties"
                new ServiceMatrix("service-matrix.properties");

                // Define used services
                Signatory signatory = Signatory.Companion.getService();
                KeyService keyService = KeyService.Companion.getService();

                // generate key pairs for issuer
                KeyId issuerKey = keyService.generate(KeyAlgorithm.ECDSA_Secp256k1);
                String issuerDid = DidService.INSTANCE.create(DidMethod.key, issuerKey.getId(),null);
                Instant expiration = Instant.now().plus(30, ChronoUnit.DAYS);

                // Prepare desired custom data that should replace the default template data
                log.info("Fetching information from authentic sources ...");
                //return authenticSourcesRemoteService.getUser(token)
                return authenticSourcesRemoteService.getUserFromLocalFile()
                        .flatMap(appUser -> {
                            log.info("Getting credential subject data for credentialType: " + credentialType + " ...");
                            Map<String, Map<String, String>> credentialSubject = appUser.getCredentialSubjectData();

                            Map<String, String> credentialSubjectData;

                            if (!credentialSubject.isEmpty()) {
                                credentialSubjectData = credentialSubject.getOrDefault(credentialType, null);
                            } else {
                                return Mono.error(new NoSuchElementException("No data saved for CredentialType " + credentialType + " and username " + username + "."));
                            }

                            Map<String, Object> data = Map.of(CREDENTIAL_SUBJECT, credentialSubjectData);

                            // Create the VC in jwt format.
                            String jwtVC = signatory.issue(
                                    credentialType,
                                    new ProofConfig(issuerDid, subjectDid,null,null, ProofType.JWT,null,null,null,null,null,null, expiration,null,null,null, Ecosystem.DEFAULT,null,"",null,null),
                                    new MergingDataProvider(data),
                                    null,
                                    false
                            );

                            //generate the signed JWT

                            Payload vcPayload;
                            try {
                                vcPayload = JOSEObject.parse(jwtVC).getPayload();
                            } catch (ParseException e) {
                                log.error("ParseException {}", e.getMessage());
                                return Mono.error(new RuntimeException(e));
                            }
                            String vcString = setIssuerDid(vcPayload).toString();

                            log.info(vcString);

                            return generateCborFromJson(vcString)
                                    .flatMap(cbor -> generateCOSEBytesFromCBOR(cbor, token))
                                    .flatMap(this::compressAndConvertToBase45FromCOSE);
                        });
            //} catch (UserDoesNotExistException e) {
            //    log.error("UserDoesNotExistException {}", e.getMessage());
            //    return Mono.error(new RuntimeException(e));
            //}
        });
    }


    /**
     * Generate CBOR payload for COSE.
     *
     * @param edgcJson EDGC payload as JSON string
     * @return Mono emitting CBOR bytes
     */
    private Mono<byte[]> generateCborFromJson(String edgcJson) {
        return Mono.fromCallable(() -> {
            CBORObject cborObject = CBORObject.FromJSONString(edgcJson);
            return cborObject.EncodeToBytes();
        });
    }

    /**
     * Generate COSE bytes from CBOR bytes.
     *
     * @param cbor  CBOR bytes
     * @param token Authentication token
     * @return Mono emitting COSE bytes
     */
    private Mono<byte[]> generateCOSEBytesFromCBOR(byte[] cbor, String token) {
        log.info("Signing credential in COSE format remotely ...");

        String cborBase64 = Base64.getEncoder().encodeToString(cbor);

        SignatureRequest signatureRequest = new SignatureRequest(
                new SignatureConfiguration(SignatureType.COSE, Collections.emptyMap()),
                cborBase64
        );

        return remoteSignatureService.sign(signatureRequest, token)
                .map(signedData -> Base64.getDecoder().decode(signedData.getData()));
    }

    /**
     * Compress COSE bytes and convert it to Base45.
     *
     * @param cose COSE Bytes
     * @return Mono emitting COSE bytes compressed and in Base45
     */
    private Mono<String> compressAndConvertToBase45FromCOSE(byte[] cose) {
        return Mono.fromCallable(() -> {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            try (CompressorOutputStream deflateOut = new CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, stream)) {
                deflateOut.write(cose);

                byte[] zip = stream.toByteArray();

                return Base45.getEncoder().encodeToString(zip);
            } catch (IOException e) {
                log.error("Error compressing and converting to Base45: " + e.getMessage(), e);
                throw new Base45Exception("Error compressing and converting to Base45");
            }
        });
    }

    public Mono<Void> commitCredentialSourceData(Payload vcPayload, String token) {
        log.info("Committing credential source data ...");

        return Mono.defer(() -> {
            Map<String, Object> vcJSON = vcPayload.toJSONObject();
            Map<String, Object> vcInfo = (Map<String, Object>) vcJSON.get("vc");
            Map<String, Object> userInfo = (Map<String, Object>) vcInfo.get(CREDENTIAL_SUBJECT);

            CommitCredentialDTO commitCredentialDTO;
            try {
                commitCredentialDTO = new CommitCredentialDTO(
                        UUID.fromString(((String) vcInfo.get("id")).split(":")[1]),
                        (String) userInfo.get("serialNumber"),
                        Utils.createDate((String) vcInfo.get("expirationDate"))
                );
            } catch (ParseException e) {
                log.error("Error creating Date {}", e.getMessage());
                return Mono.error(new CreateDateException("Error creating Date"));
            }
            return authenticSourcesRemoteService.commitCredentialSourceData(commitCredentialDTO, token)
                    .onErrorResume(e -> {
                        // Handle the exception with a custom exception
                        log.error("Error committing credential source data: " + e.getMessage());
                        return Mono.empty();
                    });
        });
    }

    public Mono<Payload> setIssuerDid(Payload vcPayload) {
        return Mono.fromSupplier(() -> {
            Map<String, Object> vcJSON = vcPayload.toJSONObject();
            vcJSON.put("iss", didElsi);

            Map<String, Object> issuerInfo = new LinkedHashMap<>();
            issuerInfo.put("id", didElsi);

            Map<String, Object> vcInfo = (Map<String, Object>) vcJSON.get("vc");
            vcInfo.put("issuer", issuerInfo);

            return new Payload(vcJSON);
        });
    }

    @Override
    public Mono<String> getVerifiableCredential(String credentialId) {
        log.info("credential ID = " + credentialId);
        return checkIfCacheExistsByState(credentialId)
                .map(VerifiableCredentialJWT::getToken);
    }

    private Mono<VerifiableCredentialJWT> checkIfCacheExistsByState(String key) {
        return Mono.defer(() -> {
            VerifiableCredentialJWT credential = credentialCacheStore.get(key);
            if (credential != null) {
                return Mono.just(credential);
            } else {
                return Mono.error(new ExpiredCacheException("Credential with id: '" + key + "' does not exist."));
            }
        });
    }

    private Mono<String> generateNonce() {
        return convertUUIDToBytes(UUID.randomUUID())
                .map(uuidBytes -> Base64URL.encode(uuidBytes).toString());
    }

    private Mono<byte[]> convertUUIDToBytes(UUID uuid) {
        return Mono.fromSupplier(() -> {
            ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
            byteBuffer.putLong(uuid.getMostSignificantBits());
            byteBuffer.putLong(uuid.getLeastSignificantBits());
            return byteBuffer.array();
        });
    }

    private Mono<String> storeTokenInCache(String token) {
        return generateNonce()
                .doOnNext(nonce -> {
                    log.debug("***** Credential Nonce code: " + nonce);
                    cacheStore.add(nonce, token);
                });
    }

    private Mono<Void> storeCredentialResponseInMemoryCache(String cNonce, String credential) {
        return Mono.fromRunnable(() -> credentialCacheStore.add(cNonce, new VerifiableCredentialJWT(credential)));
    }

    private Mono<String> getNonceClaim(String jwtProof) {
        return Mono.fromCallable(() -> {
            JWSObject jwsObject = JWSObject.parse(jwtProof);
            return jwsObject.getPayload().toJSONObject().get("nonce").toString();
        });
    }

    private Mono<Void> verifyIfUserAccessTokenIsAssociatedWithNonceOnCache(String userToken, String cacheToken) {
        return Mono.defer(() -> {
            if (userToken.equals(cacheToken)) {
                log.debug("The access token associated with the nonce matches a record in the cache");
                return Mono.empty();
            } else {
                return Mono.error(new RuntimeException("The access token associated with the nonce does not match with a record in the cache"));
            }
        });
    }
    private Mono<String> checkIfCacheExistsById(String nonce) {
        return Mono.defer(() -> {
            String cachedValue = cacheStore.get(nonce);
            if (cachedValue != null) {
                return Mono.just(cachedValue);
            } else {
                return Mono.error(new InvalidOrMissingProofException("Nonce " + nonce + " is expired or used"));
            }
        });
    }
    private Mono<String> extractDidFromJwtProof(String jwtProof) {
        return Mono.fromCallable(() -> {
            JWSObject jwsObject = JWSObject.parse(jwtProof);
            // Extract the issuer DID from the kid claim in the header
            return jwsObject.getHeader().toJSONObject().get("kid").toString();
        });
    }
}
