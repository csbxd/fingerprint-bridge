// Controlled client for the independent 3DES EtM origin test. Explicit legacy
// suites affect this fixture only. Certificate and hostname checks stay active.
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <string>

static void Require(bool ok, const char *message) {
  if (!ok) { std::cerr << message << '\n'; ERR_print_errors_fp(stderr); std::exit(1); }
}
int main(int argc, char **argv) {
  Require(argc == 3, "expected port and CA file");
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_client_method()));
  Require(ctx != nullptr, "SSL_CTX_new");
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
  Require(SSL_CTX_load_verify_locations(ctx.get(), argv[2], nullptr) == 1, "load CA");
  Require(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) &&
          SSL_CTX_set_max_proto_version(ctx.get(), TLS1_2_VERSION), "set version");
  Require(SSL_CTX_set_cipher_list(ctx.get(), "AES128-GCM-SHA256:DES-CBC3-SHA") == 1,
          "set controlled cipher offer");
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  Require(ssl != nullptr, "SSL_new");
  Require(SSL_set_tlsext_host_name(ssl.get(), "b.test") == 1 &&
          SSL_set1_host(ssl.get(), "b.test") == 1 &&
          SSL_set_bridge_encrypt_then_mac(ssl.get(), 1) == 1, "configure verified client");
  int fd = socket(AF_INET, SOCK_STREAM, 0); Require(fd >= 0, "socket");
  sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(std::atoi(argv[1]));
  address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  Require(connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0, "connect");
  Require(SSL_set_fd(ssl.get(), fd) == 1 && SSL_connect(ssl.get()) == 1, "verified handshake");
  const std::string request(std::istreambuf_iterator<char>(std::cin), {});
  Require(SSL_write(ssl.get(), request.data(), request.size()) == static_cast<int>(request.size()), "HTTP write");
  char buffer[4096]; std::string response;
  for (;;) {
    const int n=SSL_read(ssl.get(),buffer,sizeof(buffer));
    if(n<=0) break;
    response.append(buffer,n);
    const auto end=response.find("\r\n\r\n");
    const auto length=response.find("Content-Length: ");
    if(end!=std::string::npos && length!=std::string::npos &&
       response.size()>=end+4+std::stoul(response.substr(length+16))) break;
  }
  std::cout.write(response.data(), response.size());
  close(fd);
  return response.empty()?2:0;
}
