// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import org.apache.commons.codec.binary.ZBase32;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Create {@link URI URIs} for discovery of certificates in the OpenPGP Web Key Directory.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-13.html#name-key-discovery">
 *     OpenPGP Web Key Directory - §3.1. Key Discovery</a>
 */
public final class WKDAddress {

    private static final String SCHEME = "https://";
    private static final String ADV_SUBDOMAIN = "openpgpkey.";
    private static final String DIRECT_WELL_KNOWN = "/.well-known/openpgpkey/hu/";
    private static String ADV_WELL_KNOWN(String domain) {
        return "/.well-known/openpgpkey/" + domain + "/hu/";
    }

    // RegExs for Email Addresses.
    // https://www.baeldung.com/java-email-validation-regex#regular-expression-by-rfc-5322-for-email-validation
    // Modified by adding capture groups '()' for local and domain part
    private static final Pattern PATTERN_EMAIL = Pattern.compile("^([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+)@([a-zA-Z0-9.-]+)$");
    // Validate just the local part
    private static final Pattern PATTERN_LOCAL_PART = Pattern.compile("^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+$");
    // Validate just the domain part
    private static final Pattern PATTERN_DOMAIN_PART = Pattern.compile("[a-zA-Z0-9.-]+$");

    // Android API lvl 10 does not yet know StandardCharsets.UTF_8 :/
    private static final Charset utf8 = Charset.forName("UTF8");
    // Z-Base32 encoding is described in https://www.rfc-editor.org/rfc/rfc6189.html#section-5.1.6
    private static final ZBase32 zBase32 = new ZBase32();

    private final String localPart;
    private final String domainPart;
    private final String zbase32LocalPart;
    private final String percentEncodedLocalPart;

    /**
     * Construct a {@link WKDAddress} from an email address' local part and domain part.
     *
     * @param localPart local part of the email address, case-sensitive
     * @param domainPart domain part of the email address, case-insensitive
     */
    private WKDAddress(String localPart, String domainPart) {
        this.localPart = localPart;
        this.domainPart = domainPart.toLowerCase();

        this.zbase32LocalPart = sha1AndZBase32Encode(this.localPart);
        this.percentEncodedLocalPart = percentEncode(this.localPart);
    }

    /**
     * Create a new {@link WKDAddress} from an email address' local part and domain part.
     *
     * @param localPart local part of the email address, case-sensitive
     * @param domainPart domain part of the email address, case-insensitive
     *
     * @return WKD address
     */
    public static WKDAddress fromLocalAndDomainPart(String localPart, String domainPart) {
        if (!PATTERN_LOCAL_PART.matcher(localPart).matches()) {
            throw new IllegalArgumentException("Invalid local part.");
        }
        if (!PATTERN_DOMAIN_PART.matcher(domainPart).matches()) {
            throw new IllegalArgumentException("Invalid domain part.");
        }
        return new WKDAddress(localPart, domainPart);
    }

    /**
     * Transform an email address into a {@link WKDAddress} from which lookup {@link URI URIs} can be generated.
     *
     * @param email email address, case sensitive
     * @return WKDAddress object
     */
    public static WKDAddress fromEmail(String email) throws MalformedUserIdException {
        MailAddress mailAddress = parseMailAddress(email);
        return new WKDAddress(mailAddress.getLocalPart(), mailAddress.getDomainPart());
    }

    public URI getUri(DiscoveryMethod method) {
        if (method == DiscoveryMethod.advanced) {
            return getAdvancedMethodURI();
        } else if (method == DiscoveryMethod.direct) {
            return getDirectMethodURI();
        }
        throw new IllegalArgumentException("Invalid discovery method.");
    }

    public String getEmail() {
        return localPart + '@' + domainPart;
    }

    /**
     * Get an {@link URI} pointing to the certificate using the direct lookup method.
     * The direct method requires that a WKD is available on the same domain as the users mail server.
     *
     * Example URI (direct format) for email "Joe.Doe@Example.ORG":
     * <pre>https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe</pre>
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-13.html#section-3.1-10">
     *     OpenPGP Web Key Directory: §3.1. Key Discovery - Direct Method</a>
     *
     * @return URI using the direct lookup method
     */
    public URI getDirectMethodURI() {
        return URI.create(SCHEME + domainPart + DIRECT_WELL_KNOWN + zbase32LocalPart + "?l=" + percentEncodedLocalPart);
    }

    /**
     * Get an {@link URI} pointing to the certificate using the advanced lookup method.
     * The advanced method requires that a WKD is available on a special subdomain "openpgpkey" on the users mail server.
     *
     * Example URI (advanced format) for email "Joe.Doe@Example.ORG":
     * <pre>https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe</pre>
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-13.html#section-3.1-5">
     *     OpenPGP Web Key Directory: §3.1. Key Discovery - Advanced Method</a>
     *
     * @return URI using the advanced lookup method
     */
    public URI getAdvancedMethodURI() {
        return URI.create(SCHEME + ADV_SUBDOMAIN + domainPart + ADV_WELL_KNOWN(domainPart) + zbase32LocalPart + "?l=" + percentEncodedLocalPart);
    }

    /**
     * Calculate the SHA-1 hash sum of the lower-case representation of the given string and encode that using Z-Base32.
     *
     * @param string string
     * @return zbase32 encoded sha1 sum of the string
     */
    private String sha1AndZBase32Encode(String string) {
        String lowerCase = string.toLowerCase();
        byte[] bytes = lowerCase.getBytes(utf8);

        byte[] sha1;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA1");
            digest.update(bytes);
            sha1 = digest.digest();
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is a MUST on JVM implementations
            throw new AssertionError(e);
        }

        String base32KeyHandle = zBase32.encodeAsString(sha1);
        return base32KeyHandle;
    }

    /**
     * Encode a string using percent / URL encoding.
     * @param string string
     * @return percent encoded string
     */
    private String percentEncode(String string) {
        try {
            return URLEncoder.encode(string, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF8 is a MUST on JVM implementations
            throw new AssertionError(e);
        }
    }

    /**
     * Validate an email address string against the regex {@link #PATTERN_EMAIL} and split it into local and domain part.
     *
     * @param email email address string
     * @return validated and split mail address
     */
    private static MailAddress parseMailAddress(String email) throws MalformedUserIdException {
        Matcher matcher = PATTERN_EMAIL.matcher(email);
        if (!matcher.matches()) {
            throw new MalformedUserIdException("Invalid email address.");
        }

        String localPart = matcher.group(1);
        String domainPart = matcher.group(2);
        return new MailAddress(localPart, domainPart);
    }

    /**
     * Mail Address data class.
     */
    private static class MailAddress {
        private final String localPart;
        private final String domainPart;

        /**
         * Create a MailAddress object.
         * For the email address "alice@pgpainless.org", the local part would be "alice",
         * while the domain part would be "pgpainless.org".
         *
         * @param localPart local part
         * @param domainPart domain part
         */
        MailAddress(String localPart, String domainPart) {
            this.localPart = localPart;
            this.domainPart = domainPart;
        }

        /**
         * Get the local part of the email address (the part before the '@').
         * Example: "pgpainless.org"
         *
         * @return local part
         */
        public String getLocalPart() {
            return localPart;
        }

        /**
         * Get the domain part of the email address (the part after the '@').
         * Example: "alice"
         *
         * @return domain part
         */
        public String getDomainPart() {
            return domainPart;
        }
    }
}
