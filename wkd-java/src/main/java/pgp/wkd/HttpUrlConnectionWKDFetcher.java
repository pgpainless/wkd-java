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

/**
 * Implementation of {@link AbstractWKDFetcher} using Java's {@link HttpURLConnection}.
 */
public class HttpUrlConnectionWKDFetcher extends AbstractWKDFetcher {

    public InputStream fetchUri(URI uri) throws IOException {
        URL url = uri.toURL();
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
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

}
