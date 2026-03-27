// A modified version of your QUICHE-based HTTP/2 client to behave like curl:
// - Connects to a given HTTPS URL
// - Negotiates HTTP/2
// - Sends GET request
// - Prints full response body and headers
// - Closes cleanly

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bio.h"
#include "openssl/pool.h"
#include "openssl/ssl.h"
#include "openssl/stack.h"
#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/io/event_loop_socket_factory.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/masque/masque_h2_connection.h"
#include "quiche/quic/platform/api/quic_default_proof_providers.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quic_name_lookup.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"
#include "quiche/common/quiche_text_utils.h"
#include "quiche/common/simple_buffer_allocator.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(
  bool, disable_certificate_verification, false,
  "If true, don't verify the server certificate.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int, address_family, 0,
                              "IP address family to use. Must be 0, 4 or 6. "
                              "Defaults to 0 which means any.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, client_cert_file, "",
                              "Path to the client certificate chain.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, connect_target, "",
"Target host information.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
  std::string, client_cert_key_file, "",
  "Path to the pkcs8 client certificate private key.");

namespace quic {

class SimpleHttp2Client : public ConnectingClientSocket::AsyncVisitor,
                          public MasqueH2Connection::Visitor {
 public:
  SimpleHttp2Client(QuicEventLoop* loop, SSL_CTX* ctx, QuicUrl url)
      : event_loop_(loop), ctx_(ctx), url_(url) {
    socket_factory_ = std::make_unique<EventLoopSocketFactory>(loop, quiche::SimpleBufferAllocator::Get());
  }

  bool Start() {
    socket_address_ = tools::LookupAddress(AF_UNSPEC, url_.host(), absl::StrCat(url_.port()));
    if (!socket_address_.IsInitialized()) return false;
    socket_ = socket_factory_->CreateTcpClientSocket(socket_address_, 0, 0, this);
    if (!socket_) return false;
    start_time = last_http2_read_time = timeStamp();
    socket_->ConnectAsync();
    return true;
  }

  void ConnectComplete(absl::Status status) override {
    if (!status.ok()) return Finish("TCP connection failed");

    ssl_.reset(SSL_new(ctx_));
    SSL_set_app_data(ssl_.get(), this);
    static constexpr uint8_t alpn[] = {0x02, 'h', '2'};
    SSL_set_alpn_protos(ssl_.get(), alpn, sizeof(alpn));
    BIO *bio_tls = nullptr;
    BIO_new_bio_pair(&transport_io_, 16384, &bio_tls, 16384);
    SSL_set_bio(ssl_.get(), bio_tls, bio_tls);
    SSL_set_tlsext_host_name(ssl_.get(), url_.host().c_str());

    int ret = SSL_connect(ssl_.get());
    if (ret != 1 && SSL_get_error(ssl_.get(), ret) != SSL_ERROR_WANT_READ) return Finish("TLS failed");

    SendToTransport();
    if(!socket_closed_)
      socket_->ReceiveAsync(16384);
  }

  void ReceiveComplete(absl::StatusOr<quiche::QuicheMemSlice> data) override {
    if (!data.ok() || data->empty()) return Finish("Socket closed");
    std::cout << "[SD] Received Data from transport: " << data->length() << " bytes - " << timeStamp() - last_http2_read_time << "ms" << std::endl;
    last_http2_read_time = timeStamp();
    BIO_write(transport_io_, data->data(), data->length());

    if (!handshake_done_) {
      int ret = SSL_do_handshake(ssl_.get());
      if (ret != 1 && SSL_get_error(ssl_.get(), ret) != SSL_ERROR_WANT_READ) return Finish("TLS handshake failed");
      if (ret == 1) {
        handshake_done_ = true;
        h2_connection_ = std::make_unique<MasqueH2Connection>(ssl_.get(), false, this);
        h2_connection_->OnTransportReadable();
        SendRequest();
        SendToTransport();
      }
    } else {
      h2_connection_->OnTransportReadable();
    }
    SendToTransport();
    if(!socket_closed_)
      socket_->ReceiveAsync(16384);
  }

  void SendComplete(absl::Status status) override {
    if (!status.ok()) return Finish("Send failed");
  }

  void OnConnectionReady(MasqueH2Connection*) override {
    // no-op
  }

  void OnConnectionFinished(MasqueH2Connection*) override {
    done_ = true;
  }

  void OnRequest(MasqueH2Connection *connection, int32_t stream_id,
    const quiche::HttpHeaderBlock &headers,
    const std::string &body) {
    Finish("Client cannot receive requests");
  }


  void OnResponse(MasqueH2Connection*, int32_t stream_id,
                  const quiche::HttpHeaderBlock& headers,
                  const std::string& body) override {
    //std::cout << "Headers:\n" << headers.DebugString();
    //std::cout << "\nBody:\n" << body << std::endl;
    std::cout << "Total time: " << timeStamp() - start_time << "ms" << std::endl;
    socket_->Disconnect();
    socket_closed_ = true;
    done_ = true;
  }

  void SendRequest() {
    quiche::HttpHeaderBlock headers;
    headers[":method"] = "GET";
    headers[":scheme"] = url_.scheme();
    headers[":authority"] = url_.HostPort();
    headers[":path"] = url_.path();
    stream_id_ = h2_connection_->SendRequest(headers, "");
    h2_connection_->AttemptToSend();
  }

  void SendToTransport() {
    if (!socket_ || socket_closed_) return;

    char buf[16384];
    int ret = BIO_read(transport_io_, buf, sizeof(buf));
    if (ret > 0) socket_->SendAsync(std::string(buf, ret));
  }

  bool IsDone() const { return done_; }

 private:
  void Finish(const std::string& msg) {
    std::cerr << "Error: " << msg << std::endl;

    done_ = true;

    if (socket_ && !socket_closed_) {
      socket_->Disconnect();  // Cancel any pending ReceiveAsync
      socket_closed_ = true;
    }

    // Let the event loop exit cleanly
  }

  QuicEventLoop* event_loop_;
  SSL_CTX* ctx_;
  QuicUrl url_;
  std::unique_ptr<EventLoopSocketFactory> socket_factory_;
  QuicSocketAddress socket_address_;
  std::unique_ptr<ConnectingClientSocket> socket_;
  BIO* transport_io_ = nullptr;
  bssl::UniquePtr<SSL> ssl_;
  std::unique_ptr<MasqueH2Connection> h2_connection_;
  bool handshake_done_ = false;
  bool done_ = false;
  int32_t stream_id_ = -1;
  bool socket_closed_ = false;

  uint64_t start_time;
  uint64_t last_http2_read_time;
  uint64_t end_time;
  uint64_t timeStamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  }
};

int RunSimpleHttp2Client(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: simple_h2_client <url>" << std::endl;
    return 1;
  }
  QuicUrl url(argv[1]);
  quiche::QuicheSystemEventLoop loop("client");
  std::unique_ptr<QuicEventLoop> ev = GetDefaultEventLoop()->Create(QuicDefaultClock::Get());

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);

  SimpleHttp2Client client(ev.get(), ctx.get(), url);
  if (!client.Start()) return 1;

  while (!client.IsDone()) {
    ev->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(50));
  }

  return 0;
}
}

int main(int argc, char* argv[]) {
  return quic::RunSimpleHttp2Client(argc, argv);
}