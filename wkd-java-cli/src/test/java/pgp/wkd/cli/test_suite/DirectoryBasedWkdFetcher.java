// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.test_suite;

import pgp.wkd.DiscoveryMethod;
import pgp.wkd.WKDAddress;
import pgp.wkd.WKDFetcher;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Path;

public class DirectoryBasedWkdFetcher implements WKDFetcher {

    // The directory containing the .well-known subdirectory
    private final Path rootPath;

    public DirectoryBasedWkdFetcher(Path rootPath) {
        this.rootPath = rootPath;
    }

    @Override
    public InputStream fetch(WKDAddress address, DiscoveryMethod method) throws IOException {
        URI uri = address.getUri(method);
        String path = uri.getPath();
        File file = rootPath.resolve(path.substring(1)).toFile(); // get rid of leading slash at start of path
        FileInputStream fileIn = new FileInputStream(file);
        return fileIn;
    }
}
