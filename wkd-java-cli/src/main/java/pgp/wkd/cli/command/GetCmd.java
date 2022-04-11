// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.command;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import pgp.wkd.WKDAddress;
import pgp.wkd.WKDAddressHelper;
import pgp.wkd.cli.PGPainlessCertificateParser;
import pgp.wkd.cli.RuntimeIOException;
import pgp.wkd.discovery.CertificateDiscoverer;
import pgp.wkd.discovery.ValidatingCertificateDiscoverer;
import pgp.wkd.discovery.DiscoveryResult;
import pgp.wkd.discovery.HttpsUrlConnectionCertificateFetcher;
import pgp.wkd.exception.MalformedUserIdException;
import picocli.CommandLine;

import java.io.IOException;
import java.io.OutputStream;

@CommandLine.Command(
        name = "get",
        description = "Get an OpenPGP Certificate via the Web Key Directory"
)
public class GetCmd implements Runnable {

    @CommandLine.Parameters(
            index = "0",
            arity = "1",
            paramLabel = "USERID",
            description = "Certificate User-ID"
    )
    String userId;

    @CommandLine.Option(
            names = {"-a", "--armor"},
            description = "ASCII Armor the output"
    )
    boolean armor = false;

    public static final CertificateDiscoverer DEFAULT_DISCOVERER = new ValidatingCertificateDiscoverer(
            new PGPainlessCertificateParser(), new HttpsUrlConnectionCertificateFetcher());

    private static CertificateDiscoverer discoverer = DEFAULT_DISCOVERER;

    @Override
    public void run() {

        WKDAddress address = addressFromUserId(userId);
        DiscoveryResult result = discoverer.discover(address);

        OutputStream outputStream = armor ? new ArmoredOutputStream(System.out) : System.out;
        try {
            result.write(outputStream);
            if (outputStream instanceof ArmoredOutputStream) {
                outputStream.close();
            }
        } catch (IOException e) {
            // we need to wrap the ioe, since run() does not declare it
            throw new RuntimeIOException(e);
        }
    }

    public static void setCertificateDiscoverer(CertificateDiscoverer discoverer) {
        if (discoverer == null) {
            throw new NullPointerException("CertificateDiscoverer cannot be null.");
        }

        GetCmd.discoverer = discoverer;
    }

    private WKDAddress addressFromUserId(String userId) {
        String email;
        try {
            email = WKDAddressHelper.emailFromUserId(userId);
        } catch (MalformedUserIdException e) {
            email = userId;
        }

        return WKDAddress.fromEmail(email);
    }
}
