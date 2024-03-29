package es.in2.issuer.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class CredentialsSupportedTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        String expectedFormat = "sampleFormat";
        String expectedId = "sampleId";
        List<String> expectedTypes = Arrays.asList("type1", "type2");
        List<String> expectedCryptographicBindingMethods = Arrays.asList("method1", "method2");
        List<String> expectedCryptographicSuites = Arrays.asList("suite1", "suite2");
        // Act
        CredentialsSupported parameter = new CredentialsSupported(
                expectedFormat,
                expectedId,
                expectedTypes,
                expectedCryptographicBindingMethods,
                expectedCryptographicSuites,
                null
        );
        // Assert
        assertEquals(expectedFormat, parameter.format());
        assertEquals(expectedId, parameter.id());
        assertEquals(expectedTypes, parameter.types());
        assertEquals(expectedCryptographicBindingMethods, parameter.cryptographicBindingMethodsSupported());
        assertEquals(expectedCryptographicSuites, parameter.cryptographicSuitesSupported());
        assertNull(parameter.credentialSubject());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        String expectedFormat = "sampleFormat";
        String expectedId = "sampleId";
        List<String> expectedTypes = Arrays.asList("type1", "type2");
        List<String> expectedCryptographicBindingMethods = Arrays.asList("method1", "method2");
        List<String> expectedCryptographicSuites = Arrays.asList("suite1", "suite2");
        // Act
        CredentialsSupported parameter1 = new CredentialsSupported(
                expectedFormat,
                expectedId,
                expectedTypes,
                expectedCryptographicBindingMethods,
                expectedCryptographicSuites,
                null
        );
        CredentialsSupported parameter2 = parameter1;

        // Assert
        assertEquals(parameter1, parameter2); // Tests equals() method generated by Lombok
        assertEquals(parameter1.hashCode(), parameter2.hashCode()); // Tests hashCode() method generated by Lombok
    }

}
