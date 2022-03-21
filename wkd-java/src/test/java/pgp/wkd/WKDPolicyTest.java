// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import org.junit.jupiter.api.Test;
import pgp.wkd.discovery.WKDPolicy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class WKDPolicyTest {

    @Test
    public void parseEmptyPolicy() throws IOException {
        ByteArrayInputStream empty = new ByteArrayInputStream(new byte[0]);
        WKDPolicy policy = WKDPolicy.fromInputStream(empty);

        assertFalse(policy.isMailboxOnly());
        assertFalse(policy.isDaneOnly());
        assertFalse(policy.isAuthSubmit());
        assertNull(policy.getProtocolVersion());
        assertNull(policy.getSubmissionAddress());
    }

    @Test
    public void parseSparsePolicy() throws IOException {
        ByteArrayInputStream sparse = new ByteArrayInputStream(
                "protocol-version: 13\n".getBytes(StandardCharsets.UTF_8));
        WKDPolicy policy = WKDPolicy.fromInputStream(sparse);

        assertFalse(policy.isMailboxOnly());
        assertFalse(policy.isDaneOnly());
        assertFalse(policy.isAuthSubmit());
        assertEquals(13, policy.getProtocolVersion());
        assertNull(policy.getSubmissionAddress());
    }

    @Test
    public void parseFullPolicy() throws IOException {
        ByteArrayInputStream full = new ByteArrayInputStream(
                ("mailbox-only\n" +
                        "dane-only\n" +
                        "auth-submit\n" +
                        "protocol-version: 12\n" +
                        "submission-address: key-submission-example.org@directory.example.org")
                                .getBytes(StandardCharsets.UTF_8));
        WKDPolicy policy = WKDPolicy.fromInputStream(full);

        assertTrue(policy.isMailboxOnly());
        assertTrue(policy.isDaneOnly());
        assertTrue(policy.isAuthSubmit());

        assertEquals(12, policy.getProtocolVersion());
        assertEquals("key-submission-example.org@directory.example.org", policy.getSubmissionAddress());
    }
}
