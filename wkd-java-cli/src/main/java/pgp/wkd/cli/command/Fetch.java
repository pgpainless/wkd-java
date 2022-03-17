// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.command;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.io.Streams;
import pgp.certificate_store.Certificate;
import pgp.wkd.discovery.CertificateDiscoverer;
import pgp.wkd.discovery.HttpUrlConnectionCertificateFetcher;
import pgp.wkd.MalformedUserIdException;
import pgp.wkd.WKDAddress;
import pgp.wkd.WKDAddressHelper;
import pgp.wkd.discovery.DiscoveryResult;
import pgp.wkd.discovery.CertificateFetcher;
import pgp.wkd.cli.CertNotFetchableException;
import pgp.wkd.cli.DiscoverImpl;
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
    public static CertificateFetcher fetcher = new HttpUrlConnectionCertificateFetcher();

    @Override
    public void run() {
        CertificateDiscoverer certificateDiscoverer = new DiscoverImpl(fetcher);

        WKDAddress address = addressFromUserId(userId);
        DiscoveryResult result = certificateDiscoverer.discover(address);

        if (!result.isSuccessful()) {
            throw new CertNotFetchableException("Cannot fetch cert.");
        }

        try {
            if (armor) {
                OutputStream out = new ArmoredOutputStream(System.out);
                for (Certificate certificate : result.getCertificates()) {
                    Streams.pipeAll(certificate.getInputStream(), out);
                }
                out.close();
            } else {
                for (Certificate certificate : result.getCertificates()) {
                    Streams.pipeAll(certificate.getInputStream(), System.out);
                }
            }
        } catch (IOException e) {
            throw new CertNotFetchableException("Certificate cannot be fetched.", e);
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
