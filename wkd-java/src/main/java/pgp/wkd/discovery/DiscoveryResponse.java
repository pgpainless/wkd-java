// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.certificate_store.Certificate;
import pgp.wkd.RejectedCertificate;
import pgp.wkd.WKDAddress;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.Collections;
import java.util.List;

public final class DiscoveryResponse {

    private final DiscoveryMethod method;
    private final WKDAddress address;
    private final List<Certificate> certificates;
    private final List<RejectedCertificate> rejectedCertificates;
    private final Throwable fetchingFailure;

    /**
     * Constructor for a {@link DiscoveryResponse} object.
     * @param method discovery method
     * @param address wkd address used for discovery
     * @param certificates list of successfully fetched certificates
     * @param rejectedCertificates list of invalid fetched certificates (e.g. missing user-id)
     * @param fetchingFailure general fetching error (e.g. connection error, 404...)
     */
    private DiscoveryResponse(
            DiscoveryMethod method,
            WKDAddress address,
            List<Certificate> certificates,
            List<RejectedCertificate> rejectedCertificates,
            Throwable fetchingFailure) {
        this.method = method;
        this.address = address;
        this.certificates = certificates;
        this.rejectedCertificates = rejectedCertificates;
        this.fetchingFailure = fetchingFailure;
    }

    public static DiscoveryResponse success(
            @Nonnull DiscoveryMethod method,
            @Nonnull WKDAddress address,
            @Nonnull List<Certificate> certificates,
            @Nonnull List<RejectedCertificate> rejectedCertificates) {
        return new DiscoveryResponse(method, address, certificates, rejectedCertificates, null);
    }

    public static DiscoveryResponse failure(
            @Nonnull DiscoveryMethod method,
            @Nonnull WKDAddress address,
            @Nonnull Throwable fetchingFailure) {
        return new DiscoveryResponse(method, address, Collections.emptyList(), Collections.emptyList(), fetchingFailure);
    }

    @Nonnull
    public DiscoveryMethod getMethod() {
        return method;
    }

    @Nonnull
    public WKDAddress getAddress() {
        return address;
    }

    public URI getUri() {
        return getAddress().getUri(getMethod());
    }

    public boolean isSuccessful() {
        return !hasFetchingFailure();
    }

    @Nonnull
    public List<Certificate> getCertificates() {
        return certificates;
    }

    @Nonnull
    public List<RejectedCertificate> getRejectedCertificates() {
        return rejectedCertificates;
    }

    @Nullable
    public Throwable getFetchingFailure() {
        return fetchingFailure;
    }

    public boolean hasCertificates() {
        return certificates != null && !certificates.isEmpty();
    }

    public boolean hasFetchingFailure() {
        return fetchingFailure != null;
    }
}
