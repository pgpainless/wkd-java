// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * Abstract class for fetching OpenPGP certificates from the WKD.
 * This class can be extended to fetch files from remote servers using different HTTP clients.
 */
public abstract class AbstractWKDFetcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractWKDFetcher.class);

    /**
     * Attempt to fetch an OpenPGP certificate from the Web Key Directory.
     *
     * @param address WKDAddress object
     * @return input stream containing the certificate in its binary representation
     *
     * @throws IOException in case of an error
     */
    public InputStream fetch(WKDAddress address) throws IOException {
        URI advanced = address.getAdvancedMethodURI();
        IOException advancedException;
        try {
            return fetchUri(advanced);
        } catch (IOException e) {
            advancedException = e;
            LOGGER.debug("Could not fetch key using advanced method from " + advanced.toString(), advancedException);
        }

        URI direct = address.getDirectMethodURI();
        try {
            return fetchUri(direct);
        } catch (IOException e) {
            // we would like to use addSuppressed eventually, but Android API 10 does not support it
            // e.addSuppressed(advancedException);
            LOGGER.debug("Could not fetch key using direct method from " + direct.toString(), e);
            throw e;
        }
    }

    /**
     * Fetch the contents of the file that the {@link URI} points to from the remote server.
     * @param uri uri
     * @return file contents
     *
     * @throws java.net.ConnectException in case the file or host does not exist
     * @throws IOException in case of an IO-error
     */
    protected abstract InputStream fetchUri(URI uri) throws IOException;
}
