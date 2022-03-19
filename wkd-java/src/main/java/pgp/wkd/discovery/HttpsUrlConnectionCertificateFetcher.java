// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

/**
 * Implementation of {@link CertificateFetcher} using Java's {@link HttpURLConnection}.
 */
public class HttpsUrlConnectionCertificateFetcher extends AbstractUriCertificateFetcher {

    public InputStream fetchFromUri(URI uri) throws IOException {
        URL url = uri.toURL();
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setRequestMethod("GET");

        con.setConnectTimeout(5000);
        con.setReadTimeout(5000);
        con.setInstanceFollowRedirects(false);

        int status = con.getResponseCode();
        if (status != 200) {
            throw new ConnectException("Connecting to URL '" + uri + "' failed. Status: " + status);
        }
        return con.getInputStream();
    }

}
