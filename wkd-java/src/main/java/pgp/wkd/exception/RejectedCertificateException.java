// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.exception;

/**
 * Subclasses of this exception are thrown when a fetched certificate is rejected for any reason.
 */
public abstract class RejectedCertificateException extends RuntimeException {

    public RejectedCertificateException(String message) {
        super(message);
    }

    /**
     * Return an error code that identifies the exception.
     * @return error code
     */
    public abstract int getErrorCode();

    /**
     * Exception that gets thrown when an OpenPGP certificate is not carrying a User-ID binding for the email address
     * that was used to look the certificate up via WKD.
     */
    public static class MissingUserId extends RejectedCertificateException {

        public static final int ERROR_CODE = 7;

        public MissingUserId(String message) {
            super(message);
        }

        @Override
        public int getErrorCode() {
            return ERROR_CODE;
        }
    }
}
