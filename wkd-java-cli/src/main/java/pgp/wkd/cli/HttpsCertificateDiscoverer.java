package pgp.wkd.cli;

import pgp.wkd.discovery.DefaultCertificateDiscoverer;
import pgp.wkd.discovery.CertificateParser;
import pgp.wkd.discovery.HttpsUrlConnectionCertificateFetcher;
import pgp.wkd.discovery.CertificateFetcher;

public class HttpsCertificateDiscoverer extends DefaultCertificateDiscoverer {

    public HttpsCertificateDiscoverer() {
        super(new PGPainlessCertificateParser(), new HttpsUrlConnectionCertificateFetcher());
    }

    public HttpsCertificateDiscoverer(CertificateFetcher fetcher) {
        super(new PGPainlessCertificateParser(), fetcher);
    }

    public HttpsCertificateDiscoverer(CertificateParser certificateParser, CertificateFetcher fetcher) {
        super(certificateParser, fetcher);
    }
}
