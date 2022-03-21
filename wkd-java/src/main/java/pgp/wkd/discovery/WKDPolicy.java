// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import javax.annotation.Nullable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

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

    public boolean isMailboxOnly() {
        return mailboxOnly;
    }

    public boolean isDaneOnly() {
        return daneOnly;
    }

    public boolean isAuthSubmit() {
        return authSubmit;
    }

    @Nullable
    public Integer getProtocolVersion() {
        return protocolVersion;
    }

    @Nullable
    public String getSubmissionAddress() {
        return submissionAddress;
    }
}
