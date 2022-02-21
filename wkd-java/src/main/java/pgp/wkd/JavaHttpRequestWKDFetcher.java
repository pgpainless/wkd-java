// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JavaHttpRequestWKDFetcher implements IWKDFetcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaHttpRequestWKDFetcher.class);

    @Override
    public InputStream fetch(WKDAddress address) throws IOException {
        URI advanced = address.getAdvancedMethodURI();
        IOException advancedException;
        try {
            return tryFetchUri(advanced);
        } catch (IOException e) {
            advancedException = e;
            LOGGER.debug("Could not fetch key using advanced method from " + advanced.toString(), advancedException);
        }

        URI direct = address.getDirectMethodURI();
        try {
            return tryFetchUri(direct);
        } catch (IOException e) {
            // we would like to use addSuppressed eventually, but Android API 10 does no support it
            // e.addSuppressed(advancedException);
            LOGGER.debug("Could not fetch key using direct method from " + direct.toString(), e);
            throw e;
        }
    }

    private InputStream tryFetchUri(URI uri) throws IOException {
        HttpURLConnection con = getConnection(uri);
        con.setRequestMethod("GET");

        con.setConnectTimeout(5000);
        con.setReadTimeout(5000);
        con.setInstanceFollowRedirects(false);

        int status = con.getResponseCode();
        if (status != 200) {
            throw new ConnectException("Connecting to '" + uri + "' failed. Status: " + status);
        }
        return con.getInputStream();
    }

    private HttpURLConnection getConnection(URI uri) throws IOException {
        URL url = uri.toURL();
        return (HttpURLConnection) url.openConnection();
    }
}
