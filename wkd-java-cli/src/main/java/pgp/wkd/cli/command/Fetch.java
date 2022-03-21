// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.command;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import pgp.wkd.WKDAddress;
import pgp.wkd.WKDAddressHelper;
import pgp.wkd.cli.HttpsCertificateDiscoverer;
import pgp.wkd.cli.RuntimeIOException;
import pgp.wkd.discovery.CertificateDiscoverer;
import pgp.wkd.discovery.CertificateFetcher;
import pgp.wkd.discovery.DiscoveryResult;
import pgp.wkd.discovery.HttpsUrlConnectionCertificateFetcher;
import pgp.wkd.exception.MalformedUserIdException;
import picocli.CommandLine;

import java.io.IOException;
import java.io.OutputStream;

@CommandLine.Command(
        name = "fetch",
        description = "Fetch an OpenPGP Certificate via the Web Key Directory"
)
public class Fetch implements Runnable {

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

    // TODO: Better way to inject fetcher implementation
    public static CertificateFetcher fetcher = new HttpsUrlConnectionCertificateFetcher();

    @Override
    public void run() {
        CertificateDiscoverer certificateDiscoverer = new HttpsCertificateDiscoverer(fetcher);

        WKDAddress address = addressFromUserId(userId);
        DiscoveryResult result = certificateDiscoverer.discover(address);

        OutputStream outputStream = armor ? new ArmoredOutputStream(System.out) : System.out;
        try {
            result.write(outputStream);
            if (outputStream instanceof ArmoredOutputStream) {
                outputStream.close();
            }
        } catch (IOException e) {
            throw new RuntimeIOException(e);
        }
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
