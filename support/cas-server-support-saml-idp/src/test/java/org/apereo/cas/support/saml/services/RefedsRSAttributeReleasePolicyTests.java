package org.apereo.cas.support.saml.services;

import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.category.FileSystemCategory;
import org.apereo.cas.support.saml.BaseSamlIdPConfigurationTests;
import org.apereo.cas.support.saml.SamlIdPTestUtils;
import org.apereo.cas.util.CollectionUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.val;
import org.apache.commons.io.FileUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

/**
 * This is {@link RefedsRSAttributeReleasePolicyTests}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Category(FileSystemCategory.class)
public class RefedsRSAttributeReleasePolicyTests extends BaseSamlIdPConfigurationTests {
    private static final File JSON_FILE = new File(FileUtils.getTempDirectoryPath(), "RefedsRSAttributeReleasePolicyTests.json");
    private static final ObjectMapper MAPPER = new ObjectMapper().findAndRegisterModules();

    @BeforeClass
    public static void beforeClass() {
        METADATA_DIRECTORY = new FileSystemResource(FileUtils.getTempDirectory());
    }

    @Test
    public void verifyMatch() {
        val filter = new RefedsRSAttributeReleasePolicy();
        val registeredService = SamlIdPTestUtils.getSamlRegisteredService();
        registeredService.setAttributeReleasePolicy(filter);
        val attributes = filter.getAttributes(CoreAuthenticationTestUtils.getPrincipal("casuser",
            CollectionUtils.wrap("eduPersonPrincipalName", "cas-eduPerson-user")),
            CoreAuthenticationTestUtils.getService(), registeredService);
        assertFalse(attributes.isEmpty());
        assertTrue(attributes.containsKey("eduPersonPrincipalName"));
    }

    @Test
    public void verifySerializationToJson() throws IOException {
        val filter = new RefedsRSAttributeReleasePolicy();
        MAPPER.writeValue(JSON_FILE, filter);
        val strategyRead = MAPPER.readValue(JSON_FILE, RefedsRSAttributeReleasePolicy.class);
        assertEquals(filter, strategyRead);
    }
}

