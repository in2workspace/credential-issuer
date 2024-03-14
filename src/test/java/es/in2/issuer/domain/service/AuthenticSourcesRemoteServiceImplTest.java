package es.in2.issuer.domain.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.domain.exception.UserDoesNotExistException;
import es.in2.issuer.domain.model.IDEPCommitCredential;
import es.in2.issuer.domain.model.SubjectDataResponse;
import es.in2.issuer.domain.service.impl.AuthenticSourcesRemoteServiceImpl;
import es.in2.issuer.domain.util.HttpUtils;
import es.in2.issuer.infrastructure.config.AppConfiguration;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticSourcesRemoteServiceImplTest {
    @Mock
    private AppConfiguration appConfiguration;
    @Mock
    private HttpUtils httpUtils;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private AuthenticSourcesRemoteServiceImpl authenticSourcesRemoteService;

    @Test
    void testInitializeAuthenticSourcesBaseUrl() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        lenient().when(appConfiguration.getAuthenticSourcesDomain()).thenReturn(String.valueOf(Mono.just("dummyValue")));

        Method privateMethod = AuthenticSourcesRemoteServiceImpl.class.getDeclaredMethod("initializeAuthenticSourcesBaseUrl");
        privateMethod.setAccessible(true);

        privateMethod.invoke(authenticSourcesRemoteService);

        verify(appConfiguration, times(1)).getAuthenticSourcesDomain();
    }

    @Test
    void testInitializeAuthenticSourcesBaseUrlThrowsError() throws NoSuchMethodException {
        Method privateMethod = AuthenticSourcesRemoteServiceImpl.class.getDeclaredMethod("initializeAuthenticSourcesBaseUrl");
        privateMethod.setAccessible(true);

        when(appConfiguration.getAuthenticSourcesDomain()).thenAnswer(invocation -> Mono.error(new RuntimeException("Simulated error")));

        assertThrows(InvocationTargetException.class, () -> privateMethod.invoke(authenticSourcesRemoteService));

        verify(appConfiguration, times(1)).getAuthenticSourcesDomain();
    }
    @Test
    void getUser_Success() throws JsonProcessingException {

        ReflectionTestUtils.setField(authenticSourcesRemoteService,"authenticSourcesBaseUrl","http://baseurl");
        ReflectionTestUtils.setField(authenticSourcesRemoteService,"apiUsers","/api/users");

        String url = "http://baseurl" + "/api/users";
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + token));

        when(httpUtils.getRequest(url, headers))
                .thenReturn(Mono.just("{\"userId\":\"123\",\"username\":\"testUser\"}"));

        Map<String, Map<String, String>> credentialSubjectData = new HashMap<>();
        SubjectDataResponse dto = new SubjectDataResponse(credentialSubjectData);
        when(objectMapper.readValue(anyString(), eq(SubjectDataResponse.class))).thenReturn(dto);


        Mono<SubjectDataResponse> resultMono = authenticSourcesRemoteService.getUser(token);
        SubjectDataResponse result = resultMono.block();

        assertNotNull(result);

        verify(httpUtils, times(1)).getRequest(url, headers);
    }

    @Test
    void getUser_UserDoesNotExist() {
        when(httpUtils.getRequest(anyString(), anyList()))
                .thenReturn(Mono.error(new UserDoesNotExistException("invalidToken")));

        assertThrows(UserDoesNotExistException.class, this::handleUserDoesNotExist);

        verify(httpUtils, times(1)).getRequest(anyString(), anyList());
    }

    private void handleUserDoesNotExist() throws Throwable {
        try {
            authenticSourcesRemoteService.getUser("invalidToken").block();
        } catch (Exception e) {
            throw Exceptions.unwrap(e);
        }
    }

//    @Test
//    void getUser_JsonProcessingException() throws JsonProcessingException {
//        ReflectionTestUtils.setField(authenticSourcesRemoteService,"authenticSourcesBaseUrl","http://baseurl");
//        ReflectionTestUtils.setField(authenticSourcesRemoteService,"apiUsers","/api/users");
//
//        String url = "http://baseurl" + "/api/users";
//        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
//        List<Map.Entry<String, String>> headers = new ArrayList<>();
//        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + token));
//
//        when(httpUtils.getRequest(url, headers))
//                .thenReturn(Mono.just("{\"userId\":\"123\",\"username\":\"testUser\"}"));
//        when(objectMapper.readValue(anyString(), eq(SubjectDataResponse.class)))
//                .thenThrow(new JsonProcessingException("Json processing error") {});
//
//        assertThrows(RuntimeException.class, () -> handleJsonProcessingException(token));
//    }

//    private void handleJsonProcessingException(String token) throws Throwable {
//        try {
//            authenticSourcesRemoteService.getUser(token).block();
//        } catch (Exception e) {
//            throw Exceptions.unwrap(e);
//        }
//    }

    @Test
    void commitCredentialSourceData_Success() throws JsonProcessingException {
        IDEPCommitCredential idepCommitCredential = new IDEPCommitCredential(new UUID(1L, 1L), "", new Date());

        ReflectionTestUtils.setField(authenticSourcesRemoteService,"authenticSourcesBaseUrl","http://baseurl");
        ReflectionTestUtils.setField(authenticSourcesRemoteService,"apiUsers","/api/users");

        String url = "http://baseurl" + "/api/users";
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + token));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));

        when(objectMapper.writeValueAsString(idepCommitCredential)).thenReturn(idepCommitCredential.toString());
        when(httpUtils.postRequest(url, headers, idepCommitCredential.toString()))
                .thenReturn(Mono.just("{\"userId\":\"123\",\"username\":\"testUser\"}"));

        Mono<Void> resultMono = authenticSourcesRemoteService.commitCredentialSourceData(idepCommitCredential, token);

        assertDoesNotThrow(() -> resultMono.block());

        verify(httpUtils, times(1)).postRequest(url, headers, idepCommitCredential.toString());
    }

    @Test
    void commitCredentialSourceData_JsonProcessingException() throws JsonProcessingException {
        IDEPCommitCredential idepCommitCredential = new IDEPCommitCredential(new UUID(1L, 1L), "", new Date());
        String token = "validToken";
        when(objectMapper.writeValueAsString(idepCommitCredential))
                .thenThrow(new JsonProcessingException("Json processing error") {});

        assertThrows(JsonProcessingException.class, () -> {
            try {
                authenticSourcesRemoteService.commitCredentialSourceData(idepCommitCredential, token).block();
            } catch (Exception e) {
                throw Exceptions.unwrap(e);
            }
        });

        verify(httpUtils, never()).postRequest(any(), any(), any());
    }

    @Test
    void commitCredentialSourceData_ExceptionThrown() throws JsonProcessingException {
        IDEPCommitCredential idepCommitCredential = new IDEPCommitCredential(new UUID(1L, 1L), "", new Date());
        ReflectionTestUtils.setField(authenticSourcesRemoteService,"authenticSourcesBaseUrl","http://baseurl");
        ReflectionTestUtils.setField(authenticSourcesRemoteService,"apiUsers","/api/users");

        String url = "http://baseurl" + "/api/users";
        String token = "errorToken";
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + token));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));

        when(objectMapper.writeValueAsString(idepCommitCredential)).thenReturn(idepCommitCredential.toString());
        when(httpUtils.postRequest(url, headers, idepCommitCredential.toString()))
                .thenReturn(Mono.error(new RuntimeException("Simulated error")));

        Mono<Void> resultMono = authenticSourcesRemoteService.commitCredentialSourceData(idepCommitCredential, token);

        RuntimeException exception = assertThrows(RuntimeException.class, resultMono::block);
        assertTrue(exception.getMessage().contains("Simulated error"));

        verify(httpUtils, times(1)).postRequest(url, headers, idepCommitCredential.toString());
    }
}