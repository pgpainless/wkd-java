// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.command;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import pgp.wkd.IWKDFetcher;
import pgp.wkd.JavaHttpRequestWKDFetcher;
import pgp.wkd.WKDAddress;
import pgp.wkd.WKDAddressHelper;
import pgp.wkd.cli.MissingUserIdException;
import picocli.CommandLine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

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

    IWKDFetcher fetcher = new JavaHttpRequestWKDFetcher();

    @Override
    public void run() {
        String email;
        try {
            email = WKDAddressHelper.emailFromUserId(userId);
        } catch (IllegalArgumentException e) {
            email = userId;
        }

        WKDAddress address = WKDAddress.fromEmail(email);
        try (InputStream inputStream = fetcher.fetch(address)) {
            PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(inputStream);
            KeyRingInfo info = PGPainless.inspectKeyRing(cert);

            List<String> userIds = info.getValidAndExpiredUserIds();
            boolean containsEmail = false;
            for (String certUserId : userIds) {
                if (certUserId.contains("<" + email + ">") || certUserId.equals(email)) {
                    containsEmail = true;
                    break;
                }
            }
            if (!containsEmail) {
                throw new MissingUserIdException();
            }

            if (armor) {
                OutputStream out = new ArmoredOutputStream(System.out);
                cert.encode(out);
                out.close();
            } else {
                cert.encode(System.out);
            }

        } catch (IOException e) {
            System.err.println("Could not fetch certificate.");
            e.printStackTrace();
            System.exit(1);
        } catch (MissingUserIdException e) {
            System.err.println("Fetched certificate does not contain email address " + email);
            System.exit(1);
        }
    }
}