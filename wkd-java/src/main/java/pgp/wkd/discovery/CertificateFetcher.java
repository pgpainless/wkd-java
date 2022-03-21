// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.wkd.WKDAddress;

import java.io.IOException;
import java.io.InputStream;

/**
 * Abstract class for fetching OpenPGP certificates from the WKD.
 * This class can be extended to fetch files from remote servers using different HTTP clients.
 */
public interface CertificateFetcher {

    /**
     * Attempt to fetch an OpenPGP certificate from the Web Key Directory.
     *
     * @param address WKDAddress object
     * @return input stream containing the certificate in its binary representation
     *
     * @throws IOException in case of an error
     */
    InputStream fetchCertificate(WKDAddress address, DiscoveryMethod method) throws IOException;

    /**
     * Fetch the policy file belonging to the address and discovery method.
     *
     * @param address WKDAddress object
     * @param method discovery method
     * @return input stream containing the WKD policy file
     *
     * @throws IOException in case of an error
     */
    InputStream fetchPolicy(WKDAddress address, DiscoveryMethod method) throws IOException;
}
