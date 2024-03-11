package es.in2.issuer.api.service;

import es.in2.issuer.api.model.dto.AuthenticSourcesGetUserResponseDTO;
import es.in2.issuer.api.model.dto.CommitCredentialDTO;
import es.in2.issuer.api.exception.UserDoesNotExistException;
import reactor.core.publisher.Mono;

public interface AuthenticSourcesRemoteService {

    Mono<AuthenticSourcesGetUserResponseDTO> getUser(String token) throws UserDoesNotExistException;
    Mono<AuthenticSourcesGetUserResponseDTO> getUserFromLocalFile();

    Mono<Void> commitCredentialSourceData(CommitCredentialDTO commitCredentialDTO, String token);
}
