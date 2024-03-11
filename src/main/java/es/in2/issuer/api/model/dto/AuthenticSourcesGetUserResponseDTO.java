package es.in2.issuer.api.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticSourcesGetUserResponseDTO {

    @Schema(
            example = """
              {
                "LEARCredential": {
                "id": "did:key:zQ3shg2Mqz6NBj3afSySic9ynMrGk5Vgo9atHLXj4NWgxd7Xh",
                "first_name": "Francisco",
                "last_name": "Pérez García",
                "email": "francisco.perez@in2.es",
                "serialnumber": "IDCES-46521781J",
                "employeeType": "T2",
                "organizational_unit": "GDI010034",
                "organization": "GDI01"
                }
              }
        """,
            description = "The user's credential data"
    )
    @JsonProperty("credentialSubjectData")
    private Map<String, Map<String, String>> credentialSubjectData;
    //private final Map<String, Map<String, String>> credentialSubjectData;
}
