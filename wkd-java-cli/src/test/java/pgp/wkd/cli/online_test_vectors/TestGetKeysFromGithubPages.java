// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.online_test_vectors;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import pgp.wkd.cli.WKDCLI;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Disabled("For privacy reasons")
public class TestGetKeysFromGithubPages extends RedirectSystemStreamsTest {

    // Valid WKD publication.
    // Cert is available at https://pgpainless.github.io/.well-known/openpgpkey/hu/eprjcbeppbna3f6xabhtpddzpn41nknw
    private static final String USERID_BASE = "WKD Test <wkd-test-base@pgpainless.github.io> [Base Case - Valid User-ID]";
    private static final String MAIL_BASE = "wkd-test-base@pgpainless.github.io";

    @Test
    public void testFetchBaseKeyByMailAddress_Successful() {
        WKDCLI.main(new String[] {"fetch", MAIL_BASE});
        assertEquals(718, outContent.size());
    }

    @Test
    public void testFetchBaseKeyByUserID_Successful() {
        WKDCLI.main(new String[] {"fetch", USERID_BASE});
        assertEquals(718, outContent.size());
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void testFetchNonExistentKeyFails() {
        WKDCLI.main(new String[] {"fetch", "wkd-test-nonexistent@pgpainless.github,io"});
    }
}
