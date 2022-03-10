// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import pgp.certificate_store.Certificate;

import java.util.List;

public final class WKDDiscoveryItem {

    private final DiscoveryMethod method;
    private final WKDAddress address;
    private final List<Certificate> certificates;
    private final List<RejectedCertificate> rejectedCertificates;
    private final Throwable failure;

    /**
     * Constructor for a {@link WKDDiscoveryItem} object.
     * @param method discovery method
     * @param address wkd address used for discovery
     * @param certificates list of successfully fetched certificates
     * @param rejectedCertificates list of invalid fetched certificates (e.g. missing user-id)
     * @param failure general fetching error (e.g. connection error, 404...)
     */
    private WKDDiscoveryItem(
            DiscoveryMethod method,
            WKDAddress address,
            List<Certificate> certificates,
            List<RejectedCertificate> rejectedCertificates,
            Throwable failure) {
        this.method = method;
        this.address = address;
        this.certificates = certificates;
        this.rejectedCertificates = rejectedCertificates;
        this.failure = failure;
    }

    public static WKDDiscoveryItem success(DiscoveryMethod method, WKDAddress address, List<Certificate> certificates, List<RejectedCertificate> rejectedCertificates) {
        return new WKDDiscoveryItem(method, address, certificates, rejectedCertificates, null);
    }

    public static WKDDiscoveryItem failure(DiscoveryMethod method, WKDAddress address, Throwable failure) {
        return new WKDDiscoveryItem(method, address, null, null, failure);
    }

    public DiscoveryMethod getMethod() {
        return method;
    }

    public WKDAddress getAddress() {
        return address;
    }

    public boolean isSuccessful() {
        return !hasFailure();
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    public List<RejectedCertificate> getRejectedCertificates() {
        return rejectedCertificates;
    }

    public Throwable getFailure() {
        return failure;
    }

    public boolean hasCertificates() {
        return certificates != null && !certificates.isEmpty();
    }

    public boolean hasFailure() {
        return failure != null;
    }
}
