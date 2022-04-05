// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import javax.annotation.Nullable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Class describing the contents of a policy file.
 * The WKD policy file is found at ".well-known/policy"
 */
public final class WKDPolicy {

    public static final String KEYWORD_MAILBOX_ONLY = "mailbox-only";
    public static final String KEYWORD_DANE_ONLY = "dane-only";
    public static final String KEYWORD_AUTH_SUBMIT = "auth-submit";
    public static final String KEYWORD_PROTOCOL_VERSION = "protocol-version";
    public static final String KEYWORD_SUBMISSION_ADDRESS = "submission-address";

    private final boolean mailboxOnly;
    private final boolean daneOnly;
    private final boolean authSubmit;
    private final Integer protocolVersion;
    private final String submissionAddress;

    private WKDPolicy(boolean mailboxOnly, boolean daneOnly, boolean authSubmit, Integer protocolVersion, String submissionAddress) {
        this.mailboxOnly = mailboxOnly;
        this.daneOnly = daneOnly;
        this.authSubmit = authSubmit;
        this.protocolVersion = protocolVersion;
        this.submissionAddress = submissionAddress;
    }

    /**
     * Parse a {@link WKDPolicy} object by reading from the given {@link InputStream}.
     * The stream will be closed by this method.
     *
     * @param inputStream InputStream
     * @return parsed WKDPolicy object
     *
     * @throws IOException in case of an error
     */
    public static WKDPolicy fromInputStream(InputStream inputStream) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));

        boolean mailboxOnly = false;
        boolean daneOnly = false;
        boolean authSubmit = false;
        Integer protocolVersion = null;
        String submissionAddress = null;

        String line;
        while ((line = bufferedReader.readLine()) != null) {
            String prepared = line.trim();
            if (prepared.equals(KEYWORD_MAILBOX_ONLY)) {
                mailboxOnly = true;
                continue;
            }
            if (prepared.equals(KEYWORD_DANE_ONLY)) {
                daneOnly = true;
                continue;
            }
            if (prepared.equals(KEYWORD_AUTH_SUBMIT)) {
                authSubmit = true;
                continue;
            }
            if (prepared.startsWith(KEYWORD_PROTOCOL_VERSION + ": ")) {
                try {
                    protocolVersion = Integer.parseInt(prepared.substring(KEYWORD_PROTOCOL_VERSION.length() + 2));
                } catch (NumberFormatException e) {
                    // ignore
                }
                continue;
            }
            if (prepared.startsWith(KEYWORD_SUBMISSION_ADDRESS + ": ")) {
                submissionAddress = prepared.substring(KEYWORD_SUBMISSION_ADDRESS.length() + 2).trim();
            }
        }

        inputStream.close();

        return new WKDPolicy(mailboxOnly, daneOnly, authSubmit, protocolVersion, submissionAddress);
    }

    /**
     * Return <pre>true</pre> if the <pre>mailbox-only</pre> flag is set.
     *
     * The mail server provider does only accept keys with only a mailbox in the User ID.
     * In particular User IDs with a real name in addition to the mailbox will be rejected as invalid.
     *
     * @return whether mailbox-only flag is set
     */
    public boolean isMailboxOnly() {
        return mailboxOnly;
    }

    /**
     * Return <pre>true</pre> if the <pre>dane-only</pre> flag is set.
     *
     * The mail server provider does not run a Web Key Directory but only an OpenPGP DANE service.
     * The Web Key Directory Update protocol is used to update the keys for the DANE service.
     *
     * @return whether dane-only flag is set
     */
    public boolean isDaneOnly() {
        return daneOnly;
    }

    /**
     * Return <pre>true</pre> if the <pre>auth-submit</pre> flag is set.
     *
     * The submission of the mail to the server is done using an authenticated connection.
     * Thus the submitted key will be published immediately without any confirmation request.
     *
     * @return whether auth-submit flag is set
     */
    public boolean isAuthSubmit() {
        return authSubmit;
    }

    /**
     * Return the protocol version.
     *
     * This keyword can be used to explicitly claim the support of a specific version of the Web Key Directory
     * update protocol.
     * This is in general not needed but implementations may have workarounds for providers which only support
     * an old protocol version.
     * If these providers update to a newer version they should add this keyword so that the implementation
     * can disable the workaround.
     * The value is an integer corresponding to the respective draft revision number.
     *
     * @return value of the protocol-version field
     */
    @Nullable
    public Integer getProtocolVersion() {
        return protocolVersion;
    }

    /**
     * Return the <pre>submission-address</pre>.
     *
     * An alternative way to specify the submission address.
     * The value is the addr-spec part of the address to send requests to this server.
     * If this keyword is used in addition to the submission-address file, both MUST have the same value.
     *
     * @return value of the submission-address field
     */
    @Nullable
    public String getSubmissionAddress() {
        return submissionAddress;
    }
}
