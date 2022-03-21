// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import pgp.wkd.exception.MalformedUserIdException;

import javax.annotation.Nonnull;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WKDAddressHelper {

    // Firstname Lastname <email@address> [Optional Comment]
    // we are only interested in "email@address"
    private static final Pattern PATTERN_USER_ID = Pattern.compile("^.*\\<([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+)\\>.*");

    /**
     * Parse an email address from a user-id string.
     * The user-id is herein expected to follow the mail name-addr format described in RFC2822.
     *
     * Example User ID (angle normally not escaped):
     * "Slim Shady &lt;sshady@marshall-mathers.lp&gt; [Yes, the real Shady]"
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.11">
     *     RFC4880 - OpenPGP Message Format - §5.11 User ID Packet</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc2822#section-3.4">
     *     RFC2882 - Internet Message Format - §3.4 Address Specification</a>
     *
     * @param userId user-id
     * @return email address
     *
     * @throws IllegalArgumentException in case the user-id does not match the expected format
     * and does not contain an email address.
     */
    @Nonnull
    public static String emailFromUserId(String userId)
            throws MalformedUserIdException {
        Matcher matcher = PATTERN_USER_ID.matcher(userId);
        if (!matcher.matches()) {
            throw new MalformedUserIdException("User-ID does not follow excepted pattern \"Firstname Lastname <email.address> [Optional Comment]\"");
        }

        String email = matcher.group(1);
        return email;
    }

    /**
     * Create a {@link WKDAddress} by extracting an email address from the given user-id.
     *
     * @param userId user-id
     * @return WKD address for the user-id's email address.
     */
    @Nonnull
    public static WKDAddress wkdAddressFromUserId(String userId)
            throws MalformedUserIdException {
        String email = emailFromUserId(userId);
        return WKDAddress.fromEmail(email);
    }
}
