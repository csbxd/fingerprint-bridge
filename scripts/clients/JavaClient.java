import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

// JDK HttpClient + JSSE. The JVM's test-only hosts file is passed with -D.
public final class JavaClient {
    public static void main(String[] args) throws Exception {
        KeyStore roots = KeyStore.getInstance(KeyStore.getDefaultType());
        roots.load(null, null);
        try (var input = new FileInputStream(args[0])) {
            roots.setCertificateEntry("lab-ca", CertificateFactory.getInstance("X.509").generateCertificate(input));
        }
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(roots);
        var version = args[2].equals("h2") ? HttpClient.Version.HTTP_2 : HttpClient.Version.HTTP_1_1;
        for (String[] target : new String[][] {{"a.test",args[3]}, {"a.test",args[3]}, {"b.test",args[4]}}) {
            SSLContext tls = SSLContext.getInstance("TLS");
            tls.init(null, trust.getTrustManagers(), null);
            var client = HttpClient.newBuilder().sslContext(tls).version(version)
                .connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NEVER).build();
            String base = "https://" + target[0] + ":" + target[1];
            for (int n : new int[] {1,2}) {
                var request = HttpRequest.newBuilder(URI.create(base+"/fingerprint/"+n+"?encoded=%2F"))
                    .timeout(Duration.ofSeconds(15))
                    .header("User-Agent","fp-matrix/java").header("Cookie","sid=from_B; flag=yes")
                    .header("Origin",base).header("Referer",base+"/home")
                    .header("X-Order-Z","z").header("X-Order-A","a").GET().build();
                var response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode()!=200 || response.version()!=version || !response.body().equals("FP_OK")
                    || !response.headers().firstValue("set-cookie").orElse("").contains("Domain="+target[0])
                    || !response.headers().firstValue("location").orElse("").equals(base+"/next")) {
                    throw new IllegalStateException("response validation failed");
                }
            }
        }
        System.out.println(System.getProperty("java.runtime.version")+" JDK HttpClient/JSSE");
    }
}
