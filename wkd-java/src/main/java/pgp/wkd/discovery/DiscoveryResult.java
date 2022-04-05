// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.certificate_store.Certificate;
import pgp.wkd.exception.CertNotFetchableException;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Result of discovering an OpenPGP certificate via WKD.
 */
public class DiscoveryResult {

    private final List<DiscoveryResponse> items;

    /**
     * Create a {@link DiscoveryResult} from a list of {@link DiscoveryResponse DiscoveryResponses}.
     * Usually the list contains one or two responses (one for each {@link DiscoveryMethod}.
     *
     * @param items responses
     */
    public DiscoveryResult(@Nonnull List<DiscoveryResponse> items) {
        this.items = items;
    }

    /**
     * Return the list of acceptable certificates that were discovered.
     *
     * @return certificates
     */
    @Nonnull
    public List<Certificate> getCertificates() {
        List<Certificate> certificates = new ArrayList<>();

        for (DiscoveryResponse item : items) {
            if (item.isSuccessful()) {
                certificates.addAll(item.getCertificates());
            }
        }
        return certificates;
    }

    /**
     * Return true, if at least one {@link DiscoveryResponse} was successful and contained acceptable certificates.
     *
     * @return success
     */
    public boolean isSuccessful() {
        for (DiscoveryResponse item : items) {
            if (item.isSuccessful() && item.hasCertificates()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Write out the (successful) result (certificates) to the given {@link OutputStream}.
     * This method does not close the output stream.
     *
     * @param outputStream output stream
     * @throws IOException in case of an IO error
     */
    public void write(OutputStream outputStream)
            throws IOException {

        if (!isSuccessful()) {
            throwCertNotFetchableException();
        }

        byte[] buf = new byte[4096];
        int read;
        for (Certificate certificate : getCertificates()) {
            InputStream certIn = certificate.getInputStream();
            while ((read = certIn.read(buf)) != -1) {
                outputStream.write(buf, 0, read);
            }
        }
    }

    private void throwCertNotFetchableException() {
        Throwable cause = null;
        for (DiscoveryResponse response : getResponses()) {
            // Find the most "useful" exception.
            // Rejections are more useful than fetching failures
            if (!response.getRejectedCertificates().isEmpty()) {
                cause = response.getRejectedCertificates().get(0).getReasonForRejection();
                break;
            } else {
                cause = response.getFetchingFailure();
            }
        }
        throw new CertNotFetchableException("Could not fetch certificates.", cause);
    }

    /**
     * Return the list of responses.
     *
     * @return responses
     */
    @Nonnull
    public List<DiscoveryResponse> getResponses() {
        return items;
    }
}
