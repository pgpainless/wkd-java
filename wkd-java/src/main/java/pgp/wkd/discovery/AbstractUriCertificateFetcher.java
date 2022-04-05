// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.wkd.WKDAddress;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * Abstract implementation of the {@link CertificateFetcher} interface.
 * The purpose of this class is to map {@link #fetchCertificate(WKDAddress, DiscoveryMethod)}
 * and {@link #fetchPolicy(WKDAddress, DiscoveryMethod)} calls to {@link #fetchFromUri(URI)}.
 *
 * A concrete implementation of this class then simply needs to implement the latter method.
 */
public abstract class AbstractUriCertificateFetcher implements CertificateFetcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateFetcher.class);

    /**
     * Fetch the contents of the file that the {@link URI} points to from the remote server.
     * @param uri uri
     * @return file contents
     *
     * @throws java.net.ConnectException in case the file or host does not exist
     * @throws IOException in case of an IO-error
     */
    protected abstract InputStream fetchFromUri(URI uri) throws IOException;

    @Override
    public InputStream fetchCertificate(WKDAddress address, DiscoveryMethod method) throws IOException {
        URI uri = address.getUri(method);
        try {
            return fetchFromUri(uri);
        } catch (IOException e) {
            LOGGER.debug("Could not fetch key using " + method + " method from " + uri, e);
            throw e;
        }
    }

    @Override
    public InputStream fetchPolicy(WKDAddress address, DiscoveryMethod method) throws IOException {
        URI uri = address.getPolicyUri(method);
        try {
            return fetchFromUri(uri);
        } catch (IOException e) {
            LOGGER.debug("Could not fetch policy file using " + method + " method from " + uri, e);
            throw e;
        }
    }

}
