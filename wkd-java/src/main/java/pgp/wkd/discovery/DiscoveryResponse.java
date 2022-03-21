// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.certificate_store.Certificate;
import pgp.wkd.RejectedCertificate;
import pgp.wkd.WKDAddress;
import pgp.wkd.exception.MissingPolicyFileException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.List;

public final class DiscoveryResponse {

    private final DiscoveryMethod method;
    private final WKDAddress address;
    private final List<Certificate> certificates;
    private final List<RejectedCertificate> rejectedCertificates;
    private final Throwable fetchingFailure;
    private final WKDPolicy policy;
    private final MissingPolicyFileException missingPolicyFileException;

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
            Throwable fetchingFailure,
            WKDPolicy policy,
            MissingPolicyFileException missingPolicyFileException) {
        this.method = method;
        this.address = address;
        this.certificates = certificates;
        this.rejectedCertificates = rejectedCertificates;
        this.fetchingFailure = fetchingFailure;
        this.policy = policy;
        this.missingPolicyFileException = missingPolicyFileException;
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
        return !hasFetchingFailure() && hasPolicy();
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

    public boolean hasPolicy() {
        return getPolicy() != null;
    }

    @Nullable
    public WKDPolicy getPolicy() {
        return policy;
    }

    public static Builder builder(@Nonnull DiscoveryMethod discoveryMethod, @Nonnull WKDAddress address) {
        Builder builder = new Builder(discoveryMethod, address);
        return builder;
    }

    public static class Builder {

        private DiscoveryMethod discoveryMethod;
        private WKDAddress address;
        private List<Certificate> acceptableCertificates;
        private List<RejectedCertificate> rejectedCertificates;
        private Throwable fetchingFailure;
        private WKDPolicy policy;
        private MissingPolicyFileException missingPolicyFileException;

        public Builder(DiscoveryMethod discoveryMethod, WKDAddress address) {
            this.discoveryMethod = discoveryMethod;
            this.address = address;
        }

        public Builder setAcceptableCertificates(List<Certificate> acceptableCertificates) {
            this.acceptableCertificates = acceptableCertificates;
            return this;
        }

        public Builder setRejectedCertificates(List<RejectedCertificate> rejectedCertificates) {
            this.rejectedCertificates = rejectedCertificates;
            return this;
        }

        public Builder setFetchingFailure(Throwable throwable) {
            this.fetchingFailure = throwable;
            return this;
        }

        public Builder setPolicy(WKDPolicy policy) {
            this.policy = policy;
            return this;
        }

        public Builder setMissingPolicyFileException(MissingPolicyFileException exception) {
            this.missingPolicyFileException = exception;
            return this;
        }

        public DiscoveryResponse build() {
            return new DiscoveryResponse(
                    discoveryMethod,
                    address,
                    acceptableCertificates,
                    rejectedCertificates,
                    fetchingFailure,
                    policy,
                    missingPolicyFileException
            );
        }
    }
}
