// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli;

import java.io.IOException;

/**
 * {@link RuntimeException} wrapper for {@link IOException}.
 * Background: We want to throw {@link IOException IOExceptions} in {@link Runnable#run()}.
 */
public class RuntimeIOException extends RuntimeException {

    private final IOException ioException;

    public RuntimeIOException(IOException ioe) {
        super(ioe);
        this.ioException = ioe;
    }

    public IOException getIoException() {
        return ioException;
    }
}
