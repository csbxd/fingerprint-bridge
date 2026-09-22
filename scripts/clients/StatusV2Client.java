import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

// Independent JSSE client. Its default status_request_v2 extension is the
// matrix behavior the bridge must reproduce; only protocol/cipher are narrowed.
public final class StatusV2Client {
    public static void main(String[] args) throws Exception {
        KeyStore roots = KeyStore.getInstance(KeyStore.getDefaultType());
        roots.load(null, null);
        try (var input = new FileInputStream(args[0])) {
            roots.setCertificateEntry("lab-ca", CertificateFactory.getInstance("X.509").generateCertificate(input));
        }
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(roots);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trust.getTrustManagers(), null);
        SSLParameters parameters = new SSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.2"});
        parameters.setCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"});
        HttpClient client = HttpClient.newBuilder().sslContext(context).sslParameters(parameters)
            .version(HttpClient.Version.HTTP_1_1).build();
        String base = "https://b.test:" + args[1];
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/status-v2"))
            .header("Cookie", "sid=from_B; flag=yes").GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200 || !response.body().equals("STATUS_V2_OK")
            || !response.headers().firstValue("set-cookie").orElse("").contains("Domain=b.test")
            || !response.headers().firstValue("location").orElse("").equals(base + "/next")) {
            throw new IllegalStateException("response validation failed");
        }
        System.out.println("status_request_v2 OK");
    }
}
