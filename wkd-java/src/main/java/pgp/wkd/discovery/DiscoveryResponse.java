// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.certificate_store.certificate.Certificate;
import pgp.wkd.RejectedCertificate;
import pgp.wkd.WKDAddress;
import pgp.wkd.exception.MissingPolicyFileException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * A single response to a WKD query.
 */
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

    /**
     * Return the method that was used to fetch this response.
     *
     * @return method
     */
    @Nonnull
    public DiscoveryMethod getMethod() {
        return method;
    }

    /**
     * Return the WKD-Address which is queried.
     *
     * @return address
     */
    @Nonnull
    public WKDAddress getAddress() {
        return address;
    }

    /**
     * Return the URI that was queried against.
     *
     * @return URI
     */
    public URI getUri() {
        return getAddress().getUri(getMethod());
    }

    /**
     * Return true, if the query was successful.
     * That is, if there were no fetching errors, and if the server presented a policy.
     *
     * @return success
     */
    public boolean isSuccessful() {
        return !hasFetchingFailure() && hasPolicy();
    }

    /**
     * Return the list of acceptable certificates that were returned by the WKD service.
     *
     * @return certificates
     */
    @Nonnull
    public List<Certificate> getCertificates() {
        return certificates;
    }

    /**
     * Return a list containing all rejected certificates returned by the WKD service.
     * Certificates can be rejected for several reasons such as a missing user-id, or if the certificate is malformed.
     *
     * @return list of rejected certificates
     */
    @Nonnull
    public List<RejectedCertificate> getRejectedCertificates() {
        return rejectedCertificates;
    }

    /**
     * Return the cause of fetching errors, if any.
     * A fetching failure might be e.g. a connection exception in case the WKD service cannot be reached.
     *
     * @return fetching failure
     */
    @Nullable
    public Throwable getFetchingFailure() {
        return fetchingFailure;
    }

    /**
     * Return true, if the result contains acceptable certificates.
     *
     * @return true if the response has certificates
     */
    public boolean hasCertificates() {
        return certificates != null && !certificates.isEmpty();
    }

    /**
     * Return true, if there was a fetching failure.
     *
     * @return true if failure
     */
    public boolean hasFetchingFailure() {
        return fetchingFailure != null;
    }

    /**
     * Return true, if the WKD service presented a policy.
     *
     * @return true if policy available
     */
    public boolean hasPolicy() {
        return getPolicy() != null;
    }

    @Nullable
    public WKDPolicy getPolicy() {
        return policy;
    }

    /**
     * Builder for {@link DiscoveryResponse}.
     *
     * @param discoveryMethod method used for discovery
     * @param address WKD address
     * @return builder
     */
    static Builder builder(@Nonnull DiscoveryMethod discoveryMethod, @Nonnull WKDAddress address) {
        return new Builder(discoveryMethod, address);
    }

    static class Builder {

        private DiscoveryMethod discoveryMethod;
        private WKDAddress address;
        private List<Certificate> acceptableCertificates = new ArrayList<>();
        private List<RejectedCertificate> rejectedCertificates = new ArrayList<>();
        private Throwable fetchingFailure;
        private WKDPolicy policy;
        private MissingPolicyFileException missingPolicyFileException;

        Builder(DiscoveryMethod discoveryMethod, WKDAddress address) {
            this.discoveryMethod = discoveryMethod;
            this.address = address;
        }

        Builder setAcceptableCertificates(List<Certificate> acceptableCertificates) {
            this.acceptableCertificates = acceptableCertificates;
            return this;
        }

        Builder setRejectedCertificates(List<RejectedCertificate> rejectedCertificates) {
            this.rejectedCertificates = rejectedCertificates;
            return this;
        }

        Builder setFetchingFailure(Throwable throwable) {
            this.fetchingFailure = throwable;
            return this;
        }

        Builder setPolicy(WKDPolicy policy) {
            this.policy = policy;
            return this;
        }

        Builder setMissingPolicyFileException(MissingPolicyFileException exception) {
            this.missingPolicyFileException = exception;
            return this;
        }

        DiscoveryResponse build() {
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
