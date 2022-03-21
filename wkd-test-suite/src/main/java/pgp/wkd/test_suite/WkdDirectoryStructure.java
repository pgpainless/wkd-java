// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;

import pgp.wkd.WKDAddress;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;

public abstract class WkdDirectoryStructure {

    protected final String domain;
    protected final File rootDir;
    protected final File wellKnown;
    protected final File openpgpkey;

    public WkdDirectoryStructure(File rootDirectory, String domain) {
        this.domain = domain;
        this.rootDir = rootDirectory;
        wellKnown = new File(rootDirectory, ".well-known");
        openpgpkey = new File(wellKnown, "openpgpkey");
    }

    public abstract File getHu();

    public abstract Path getRelativeCertificatePath(String mailAddress);

    public abstract void mkdirs() throws IOException;

    protected void mkdir(File dir) throws IOException {
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Cannot create directory '" + dir.getAbsolutePath() + "'.");
        }
        if (dir.isFile()) {
            throw new IOException("Cannot create directory '" + dir.getAbsolutePath() + "': Is a file.");
        }
    }

    protected void touch(File file) throws IOException {
        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Cannot create file '" + file.getAbsolutePath() + "'.");
        }
        if (!file.isFile()) {
            throw new IOException("Cannot create file '" + file.getAbsolutePath() + "': Is not a file.");
        }
    }

    public abstract URI getAddress(String mail);

    public abstract File resolve(Path path);

    public static class DirectMethod extends WkdDirectoryStructure {

        private final File hu;
        private final File policy;

        public DirectMethod(File rootDirectory, String domain) {
            super(rootDirectory, domain);
            this.hu = new File(openpgpkey, "hu");
            this.policy = new File(openpgpkey, "policy");
        }

        @Override
        public File getHu() {
            return hu;
        }

        @Override
        public Path getRelativeCertificatePath(String mailAddress) {
            WKDAddress address = WKDAddress.fromEmail(mailAddress);
            String path = address.getDirectMethodURI().getPath();
            String fileName = path.substring(path.lastIndexOf('/') + 1);
            return rootDir.toPath().relativize(new File(getHu(), fileName).toPath());
        }

        @Override
        public void mkdirs() throws IOException {
            mkdir(rootDir);
            mkdir(wellKnown);
            mkdir(openpgpkey);
            mkdir(hu);

            touch(policy);
        }

        @Override
        public URI getAddress(String mail) {
            return WKDAddress.fromEmail(mail).getDirectMethodURI();
        }

        @Override
        public File resolve(Path path) {
            return rootDir.toPath().resolve(path).toFile();
        }
    }

    public static class AdvancedMethod extends WkdDirectoryStructure {

        private final File domainFile;
        private final File hu;
        private final File policy;

        public AdvancedMethod(File rootDir, String domain) {
            super(rootDir, domain);
            this.domainFile = new File(openpgpkey, domain);
            this.hu = new File(domainFile, "hu");
            this.policy = new File(domainFile, "policy");
        }

        @Override
        public File getHu() {
            return hu;
        }

        @Override
        public Path getRelativeCertificatePath(String mailAddress) {
            WKDAddress address = WKDAddress.fromEmail(mailAddress);
            String path = address.getAdvancedMethodURI().getPath();
            String fileName = path.substring(path.lastIndexOf('/') + 1);
            return rootDir.toPath().relativize(new File(getHu(), fileName).toPath());
        }

        @Override
        public void mkdirs() throws IOException {
            mkdir(rootDir);
            mkdir(wellKnown);
            mkdir(openpgpkey);
            mkdir(domainFile);
            mkdir(hu);

            touch(policy);
        }

        @Override
        public URI getAddress(String mail) {
            return WKDAddress.fromEmail(mail).getAdvancedMethodURI();
        }

        @Override
        public File resolve(Path path) {
            return rootDir.toPath().resolve(path).toFile();
        }
    }
}
