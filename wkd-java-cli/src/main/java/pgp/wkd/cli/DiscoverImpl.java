package pgp.wkd.cli;

import pgp.wkd.discovery.CertificateDiscoveryImplementation;
import pgp.wkd.discovery.CertificateParser;
import pgp.wkd.discovery.HttpUrlConnectionCertificateFetcher;
import pgp.wkd.discovery.CertificateFetcher;

public class DiscoverImpl extends CertificateDiscoveryImplementation {

    public DiscoverImpl() {
        super(new CertificateParserImpl(), new HttpUrlConnectionCertificateFetcher());
    }

    public DiscoverImpl(CertificateFetcher fetcher) {
        super(new CertificateParserImpl(), fetcher);
    }

    public DiscoverImpl(CertificateParser certificateParser, CertificateFetcher fetcher) {
        super(certificateParser, fetcher);
    }
}
