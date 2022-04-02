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

public class DiscoveryResult {

    private List<DiscoveryResponse> items;

    public DiscoveryResult(@Nonnull List<DiscoveryResponse> items) {
        this.items = items;
    }

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
        for (DiscoveryResponse response : getItems()) {
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

    @Nonnull
    public List<DiscoveryResponse> getItems() {
        return items;
    }

    @Nonnull
    public List<DiscoveryResponse> getFailedItems() {
        List<DiscoveryResponse> fails = new ArrayList<>();
        for (DiscoveryResponse item : items) {
            if (!item.isSuccessful()) {
                fails.add(item);
            }
        }
        return fails;
    }
}
