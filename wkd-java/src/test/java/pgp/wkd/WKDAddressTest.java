// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import pgp.wkd.discovery.DiscoveryMethod;
import pgp.wkd.exception.MalformedUserIdException;

public class WKDAddressTest {

    @Test
    public void testAdvancedFromUserId() {
        String userId = "Joe Doe <Joe.Doe@Example.ORG> [Work Address]";
        URI expectedURI = URI.create("https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");

        WKDAddress address = WKDAddressHelper.wkdAddressFromUserId(userId);
        URI actual = address.getAdvancedMethodURI();
        assertEquals(expectedURI, actual);
    }

    @Test
    public void testDirectFromUserId() {
        String userId = "<alice@pgpainless.org>";
        URI expected = URI.create("https://pgpainless.org/.well-known/openpgpkey/hu/kei1q4tipxxu1yj79k9kfukdhfy631xe?l=alice");

        WKDAddress address = WKDAddressHelper.wkdAddressFromUserId(userId);
        URI actual = address.getDirectMethodURI();
        assertEquals(expected, actual);
    }

    @Test
    public void testDirectFromEmail() {
        String mailAddress = "Joe.Doe@Example.ORG";
        URI expected = URI.create("https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");

        WKDAddress address = WKDAddress.fromEmail(mailAddress);
        URI actual = address.getDirectMethodURI();
        assertEquals(expected, actual);
    }

    @Test
    public void testAdvancedFromEmail() {
        String mailAddress = "Joe.Doe@Example.ORG";
        URI expected = URI.create("https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");

        WKDAddress address = WKDAddress.fromEmail(mailAddress);
        URI actual = address.getAdvancedMethodURI();
        assertEquals(expected, actual);
    }

    @Test
    public void testFromInvalidUserid() {
        for (String brokenUserId : Arrays.asList(
                "Alice <alice>",
                "Alice <alice@example.org",
                "Alice",
                "John Doe <john doe@example.org>",
                "John Doe <john.doe@example org>",
                "John Doe <john<example.org>",
                "John Doe [The Real One]",
                "<John Doe",
                "Don Joeh>")) {
            assertThrows(MalformedUserIdException.class, () -> WKDAddressHelper.wkdAddressFromUserId(brokenUserId));
        }
    }

    @Test
    public void fromLocalAndDomainPartTest() {
        String validLocalPart = "Alice93";
        String validDomainPart = "pgpainless.org";

        String invalidLocalPart = "contains whitespace";
        String invalidDomainPart = "contains white.space";

        WKDAddress address = WKDAddress.fromLocalAndDomainPart(validLocalPart, validDomainPart);
        assertEquals("Alice93@pgpainless.org", address.getEmail());

        assertThrows(IllegalArgumentException.class, () -> WKDAddress.fromLocalAndDomainPart(invalidLocalPart, validDomainPart));
        assertThrows(IllegalArgumentException.class, () -> WKDAddress.fromLocalAndDomainPart(validLocalPart, invalidDomainPart));
        assertThrows(IllegalArgumentException.class, () -> WKDAddress.fromLocalAndDomainPart(invalidLocalPart, invalidDomainPart));
    }

    @Test
    public void testFromInvalidEmail() {
        for (String brokenEmail : Arrays.asList("john.doe", "@example.org", "john doe@example.org", "john.doe@example org")) {
            assertThrows(MalformedUserIdException.class, () -> WKDAddress.fromEmail(brokenEmail));
        }
    }

    @Test
    public void testDirectPolicyUri() {
        WKDAddress address = WKDAddress.fromEmail("alice@pgpainless.org");
        assertEquals("https://pgpainless.org/.well-known/openpgpkey/policy", address.getDirectMethodPolicyURI().toString());
    }

    @Test
    public void testAdvancedPolicyUri() {
        WKDAddress address = WKDAddress.fromEmail("alice@pgpainless.org");
        assertEquals("https://openpgpkey.pgpainless.org/.well-known/openpgpkey/pgpainless.org/policy", address.getAdvancedMethodPolicyURI().toString());
    }

    @Test
    public void testPolicyUriByMethod() {
        WKDAddress address = WKDAddress.fromEmail("bob@example.com");
        assertEquals(address.getAdvancedMethodPolicyURI(), address.getPolicyUri(DiscoveryMethod.advanced));
        assertEquals(address.getDirectMethodPolicyURI(), address.getPolicyUri(DiscoveryMethod.direct));
    }
}
