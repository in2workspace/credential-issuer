package es.in2.issuer.api.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.api.config.azure.AppConfigurationKeys;
import es.in2.issuer.api.model.dto.CredentialIssuerMetadata;
import es.in2.issuer.api.model.dto.CredentialOfferForPreAuthorizedCodeFlow;
import es.in2.issuer.api.model.dto.CredentialsSupportedParameter;
import es.in2.issuer.api.exception.ExpiredPreAuthorizedCodeException;
import es.in2.issuer.api.repository.CacheStore;
import es.in2.issuer.api.service.AppConfigService;
import es.in2.issuer.api.service.AzureKeyVaultService;
import es.in2.issuer.api.service.CredentialIssuerMetadataService;
import es.in2.issuer.api.util.HttpUtils;
import es.in2.issuer.api.util.Utils;
import id.walt.credentials.w3c.templates.VcTemplateService;
import id.walt.servicematrix.ServiceMatrix;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import static es.in2.issuer.api.util.Constants.LEAR_CREDENTIAL;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    @Mock
    private AppConfigService appConfigService;

    @Mock
    private AzureKeyVaultService azureKeyVaultService;

    @Mock
    private CacheStore<CredentialOfferForPreAuthorizedCodeFlow> cacheStore;

    @Mock
    private HttpUtils httpUtils;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CredentialIssuerMetadataService credentialIssuerMetadataService;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;


    @Test
    void testInitializeAzureProperties() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        lenient().when(appConfigService.getConfiguration(any())).thenReturn(Mono.just("dummyValue"));
        lenient().when(azureKeyVaultService.getSecretByKey(any())).thenReturn(Mono.just("dummyValue"));

        Method privateMethod = CredentialOfferServiceImpl.class.getDeclaredMethod("initializeAzureProperties");
        privateMethod.setAccessible(true);

        privateMethod.invoke(credentialOfferService);

        verify(appConfigService, times(1)).getConfiguration(AppConfigurationKeys.ISSUER_VCI_BASE_URL_KEY);
        verify(appConfigService, times(1)).getConfiguration(AppConfigurationKeys.KEYCLOAK_URI_KEY);
        verify(azureKeyVaultService, times(1)).getSecretByKey(AppConfigurationKeys.DID_ISSUER_KEYCLOAK_SECRET);

    }

    @Test
    void testInitializeAzurePropertiesThrowsErrorOnKeyVaultService() throws NoSuchMethodException {

        Method privateMethod = CredentialOfferServiceImpl.class.getDeclaredMethod("initializeAzureProperties");
        privateMethod.setAccessible(true);

        lenient().when(appConfigService.getConfiguration(any())).thenReturn(Mono.just("dummyValue"));
        lenient().when(azureKeyVaultService.getSecretByKey(any())).thenReturn(Mono.error(new RuntimeException("Simulated error")));

        assertThrows(InvocationTargetException.class, () -> privateMethod.invoke(credentialOfferService));

        verify(appConfigService, times(1)).getConfiguration(AppConfigurationKeys.ISSUER_VCI_BASE_URL_KEY);
        verify(appConfigService, times(1)).getConfiguration(AppConfigurationKeys.KEYCLOAK_URI_KEY);
        verify(azureKeyVaultService, times(1)).getSecretByKey(AppConfigurationKeys.DID_ISSUER_KEYCLOAK_SECRET);

    }

    @Test
    void testInitializeAzurePropertiesThrowsErrorOnAppConfigService() throws NoSuchMethodException {

        Method privateMethod = CredentialOfferServiceImpl.class.getDeclaredMethod("initializeAzureProperties");
        privateMethod.setAccessible(true);

        lenient().when(appConfigService.getConfiguration(any())).thenReturn(Mono.error(new RuntimeException("Simulated error")));
        lenient().when(azureKeyVaultService.getSecretByKey(any())).thenReturn(Mono.just("dummyValue"));

        assertThrows(InvocationTargetException.class, () -> privateMethod.invoke(credentialOfferService));

        verify(appConfigService, times(1)).getConfiguration(AppConfigurationKeys.ISSUER_VCI_BASE_URL_KEY);
        verify(azureKeyVaultService, times(0)).getSecretByKey(AppConfigurationKeys.DID_ISSUER_KEYCLOAK_SECRET);

    }

    // TODO : Mock waltid services call

//    @Test
//    void testCreateCredentialOfferUriForPreAuthorizedCodeFlow() throws JsonProcessingException {
//        new ServiceMatrix(Utils.SERVICE_MATRIX_PATH);
//
//        ReflectionTestUtils.setField(credentialOfferService,"issuerApiBaseUrl","http://baseUrl");
//        ReflectionTestUtils.setField(credentialOfferService,"issuerUri","issuerUri");
//        ReflectionTestUtils.setField(credentialOfferService,"did","did");
//
//        String preAuthCodeUri = "issuerUri/realms/EAAProvider/verifiable-credential/did/credential-offer";
//        String url = preAuthCodeUri + "?type=VerifiableId&format=jwt_vc_json";
//
//        String accessToken = "dummyAccessToken";
//        List<CredentialsSupportedParameter> supportedParameters = Arrays.asList(
//                new CredentialsSupportedParameter(
//                        "jwt_vc_json",
//                        "VerifiableId_JWT",
//                        Arrays.asList("VerifiableCredential", "VerifiableAttestation", "VerifiableId"),
//                        List.of("did"),
//                        new ArrayList<>(),
//                        VcTemplateService.Companion.getService().getTemplate("VerifiableId",true,VcTemplateService.SAVED_VC_TEMPLATES_KEY)
//                ),
//                new CredentialsSupportedParameter(
//                        "jwt_vc_json",
//                        LEAR_CREDENTIAL,
//                        Arrays.asList("VerifiableCredential", "VerifiableAttestation", "LEARCredential"),
//                        List.of("did"),
//                        new ArrayList<>(),
//                        VcTemplateService.Companion.getService().getTemplate("LEARCredential",true,"")
//                ));
//
//        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata("credentialIssuer","credentialEndpoint","credentialToken", supportedParameters );
//
//        when(credentialIssuerMetadataService.generateOpenIdCredentialIssuer()).thenReturn(Mono.just(credentialIssuerMetadata));
//
//        List<Map.Entry<String, String>> headers = new ArrayList<>();
//        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken));
//        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
//
//        String jsonString = "{\"grants\":{\"pre-authorized_code\":\"your_pre_authorized_code_here\"}}";
//        when(httpUtils.getRequest(url,headers)).thenReturn(Mono.just(jsonString));
//        JsonNode jsonObject = new ObjectMapper().convertValue(jsonString, JsonNode.class);
//        when(objectMapper.readTree(jsonString)).thenReturn(jsonObject);
//
//        String result = credentialOfferService.createCredentialOfferUriForPreAuthorizedCodeFlow(accessToken, LEAR_CREDENTIAL).block();
//
//        assertNotNull(result);
//
//    }

    // TODO : Mock waltid services call

//    @Test
//    void testGenerateCredentialOffer() throws JsonProcessingException {
//        new ServiceMatrix(Utils.SERVICE_MATRIX_PATH);
//
//        ReflectionTestUtils.setField(credentialOfferService,"issuerUri","issuerUri");
//        ReflectionTestUtils.setField(credentialOfferService,"did","did");
//
//        String preAuthCodeUri = "issuerUri/realms/EAAProvider/verifiable-credential/did/credential-offer";
//        String url = preAuthCodeUri + "?type=VerifiableId&format=jwt_vc_json";
//
//        String accessToken = "dummyAccessToken";
//        List<CredentialsSupportedParameter> supportedParameters = Arrays.asList(
//                new CredentialsSupportedParameter(
//                        "jwt_vc_json",
//                        "VerifiableId_JWT",
//                        Arrays.asList("VerifiableCredential", "VerifiableAttestation", "VerifiableId"),
//                        List.of("did"),
//                        new ArrayList<>(),
//                        VcTemplateService.Companion.getService().getTemplate("VerifiableId",true,VcTemplateService.SAVED_VC_TEMPLATES_KEY)
//                ),
//                new CredentialsSupportedParameter(
//                        "jwt_vc_json",
//                        LEAR_CREDENTIAL,
//                        Arrays.asList("VerifiableCredential", "VerifiableAttestation", "LEARCredential"),
//                        List.of("did"),
//                        new ArrayList<>(),
//                        VcTemplateService.Companion.getService().getTemplate("LEARCredential",true,"")
//                ));
//
//        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata("credentialIssuer","credentialEndpoint","credentialToken", supportedParameters );
//
//        when(credentialIssuerMetadataService.generateOpenIdCredentialIssuer()).thenReturn(Mono.just(credentialIssuerMetadata));
//
//        List<Map.Entry<String, String>> headers = new ArrayList<>();
//        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken));
//        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
//
//        String jsonString = "{\"grants\":{\"pre-authorized_code\":\"your_pre_authorized_code_here\"}}";
//        when(httpUtils.getRequest(url,headers)).thenReturn(Mono.just(jsonString));
//        JsonNode jsonObject = new ObjectMapper().convertValue(jsonString, JsonNode.class);
//        when(objectMapper.readTree(jsonString)).thenReturn(jsonObject);
//
//        // Call method
//        Mono<String> result = credentialOfferService.generateCredentialOffer(accessToken, LEAR_CREDENTIAL);
//
//        String dummyNonce = "XvmPFalLQWKdfnXcDUvAOA";
//        // Assertions
//        assertNotNull(result);
//        assertEquals(dummyNonce.length(), result.block().length());
//        verify(credentialIssuerMetadataService, times(1)).generateOpenIdCredentialIssuer();
//        verify(httpUtils, times(1)).getRequest(url,headers);
//        verify(objectMapper, times(1)).readTree(jsonString);
//
//    }


    // TODO : Mock waltid services call

//    @Test
//    void testGenerateCredentialOfferWithNullCredentialType() throws JsonProcessingException {
//        new ServiceMatrix(Utils.SERVICE_MATRIX_PATH);
//
//        ReflectionTestUtils.setField(credentialOfferService,"issuerUri","issuerUri");
//        ReflectionTestUtils.setField(credentialOfferService,"did","did");
//
//        String preAuthCodeUri = "issuerUri/realms/EAAProvider/verifiable-credential/did/credential-offer";
//        String url = preAuthCodeUri + "?type=VerifiableId&format=jwt_vc_json";
//
//        String accessToken = "dummyAccessToken";
//        List<CredentialsSupportedParameter> supportedParameters = Arrays.asList(
//                new CredentialsSupportedParameter(
//                        "jwt_vc_json",
//                        "VerifiableId_JWT",
//                        Arrays.asList("VerifiableCredential", "VerifiableAttestation", "VerifiableId"),
//                        List.of("did"),
//                        new ArrayList<>(),
//                        VcTemplateService.Companion.getService().getTemplate("VerifiableId",true,VcTemplateService.SAVED_VC_TEMPLATES_KEY)
//                ),
//                new CredentialsSupportedParameter(
//                        "jwt_vc_json",
//                        LEAR_CREDENTIAL,
//                        Arrays.asList("VerifiableCredential", "VerifiableAttestation", "LEARCredential"),
//                        List.of("did"),
//                        new ArrayList<>(),
//                        VcTemplateService.Companion.getService().getTemplate("LEARCredential",true,"")
//                ));
//
//        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata("credentialIssuer","credentialEndpoint","credentialToken", supportedParameters );
//
//        when(credentialIssuerMetadataService.generateOpenIdCredentialIssuer()).thenReturn(Mono.just(credentialIssuerMetadata));
//
//        List<Map.Entry<String, String>> headers = new ArrayList<>();
//        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken));
//        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
//
//        String jsonString = "{\"grants\":{\"pre-authorized_code\":\"your_pre_authorized_code_here\"}}";
//        when(httpUtils.getRequest(url,headers)).thenReturn(Mono.just(jsonString));
//        JsonNode jsonObject = new ObjectMapper().convertValue(jsonString, JsonNode.class);
//        when(objectMapper.readTree(jsonString)).thenReturn(jsonObject);
//
//        // Call method
//        Mono<String> result = credentialOfferService.generateCredentialOffer(accessToken, null);
//
//        String dummyNonce = "XvmPFalLQWKdfnXcDUvAOA";
//        // Assertions
//        assertNotNull(result);
//        assertEquals(dummyNonce.length(), result.block().length());
//        verify(credentialIssuerMetadataService, times(1)).generateOpenIdCredentialIssuer();
//        verify(httpUtils, times(1)).getRequest(url,headers);
//        verify(objectMapper, times(1)).readTree(jsonString);
//
//    }

    @Test
    void testGetCredentialOffer() {
        String id = "dummyId";
        CredentialOfferForPreAuthorizedCodeFlow credentialOffer = new CredentialOfferForPreAuthorizedCodeFlow();

        when(cacheStore.get(id)).thenReturn(credentialOffer);
        doNothing().when(cacheStore).delete(any());

        Mono<CredentialOfferForPreAuthorizedCodeFlow> result = credentialOfferService.getCredentialOffer(id);

        assertEquals(credentialOffer, result.block());
        verify(cacheStore, times(1)).delete(id);
    }

    @Test
    void testGetCredentialOfferTheReturnExpiredPreAuthorizedCodeException() {
        // Mocking
        String id = "nonExistentId";

        when(cacheStore.get(any())).thenReturn(null);

        assertThrows(ExpiredPreAuthorizedCodeException.class, () -> {
            try {
                credentialOfferService.getCredentialOffer(id).block();
            } catch (Exception e) {
                throw Exceptions.unwrap(e);
            }
        });

        verify(cacheStore, times(1)).get(id);
        verify(cacheStore, times(0)).delete(id);

    }
}