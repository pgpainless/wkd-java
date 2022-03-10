// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

public abstract class AbstractUriWKDFetcher implements WKDFetcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(WKDFetcher.class);

    @Override
    public InputStream fetch(WKDAddress address, DiscoveryMethod method) throws IOException {
        URI uri = address.getUri(method);
        try {
            return fetchUri(uri);
        } catch (IOException e) {
            LOGGER.debug("Could not fetch key using " + method + " method from " + uri.toString(), e);
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
