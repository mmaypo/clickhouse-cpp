// app.cpp
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "clickhouse/client.h"
#include "openssl/err.h"
#include "openssl/ssl.h"

#ifdef _WIN32
#include <in6addr.h>
#include <winsock2.h>
#include <ws2tcpip.h>  // InetNtopA / InetNtopW
#else
#include <arpa/inet.h>   // inet_ntop / inet_pton
#include <netinet/in.h>  // in6_addr
#include <netinet/in.h>
#endif

constexpr const bool use_mtls = true;

static std::string OpenSSLErrorString() {
    unsigned long err = ERR_get_error();
    if (err == 0) return {};
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

// Represent IPv6 as 16 raw bytes(network byte order).
struct alignas(in6_addr) AlignedIPv6Bytes {
    std::array<uint8_t, 16> bytes{};

    uint8_t* data() noexcept { return bytes.data(); }
    const uint8_t* data() const noexcept { return bytes.data(); }

    static constexpr std::size_t size() noexcept { return 16; }
};
using IPv6Bytes = AlignedIPv6Bytes;

static_assert(sizeof(in6_addr) == 16, "Unexpected in6_addr size");
static_assert(alignof(in6_addr) <= alignof(IPv6Bytes), "Alignment may be insufficient");

inline const in6_addr& as_in6_addr_ref(const IPv6Bytes& b) noexcept {
    return *reinterpret_cast<const in6_addr*>(b.data());
}

inline in6_addr& as_in6_addr_ref(IPv6Bytes& b) noexcept {
    return *reinterpret_cast<in6_addr*>(b.data());
}

void AppendNullableIPv6(clickhouse::ColumnIPv6& data, clickhouse::ColumnUInt8& nulls, const std::optional<IPv6Bytes>& v) {
    if (v) {
        data.Append(as_in6_addr_ref(*v));  // raw 16-byte IPv6 value
        nulls.Append(static_cast<uint8_t>(0));
    } else {
        data.Append(as_in6_addr_ref(IPv6Bytes{}));  // ignored when nulls=1, but must be a valid value
        nulls.Append(static_cast<uint8_t>(1));
    }
}

IPv6Bytes IPv4Mapped(uint32_t ipv4_be /* ipv4_be MUST be big-endian */) {
    IPv6Bytes out{};
    auto* p = out.data();  // 16 bytes
    p[10]   = 0xff;
    p[11]   = 0xff;
    p[12]   = static_cast<uint8_t>((ipv4_be >> 24) & 0xff);
    p[13]   = static_cast<uint8_t>((ipv4_be >> 16) & 0xff);
    p[14]   = static_cast<uint8_t>((ipv4_be >> 8) & 0xff);
    p[15]   = static_cast<uint8_t>((ipv4_be >> 0) & 0xff);
    return out;
}

// Example raw bytes for documentation prefix 2001:db8::/32:
// 2001:db8::1  -> {0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1}
const IPv6Bytes ip_2001_db8__1 = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

// 2001:db8::2  -> ... last byte 0x02
const IPv6Bytes ip_2001_db8__2 = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

int main() {
    using clickhouse::Block;
    using clickhouse::Client;
    using clickhouse::ClientOptions;
    using clickhouse::ColumnIPv6;
    using clickhouse::ColumnNullable;
    using clickhouse::ColumnString;
    using clickhouse::ColumnUInt16;
    using clickhouse::ColumnUInt32;
    using clickhouse::ColumnUInt64;
    using clickhouse::ColumnUInt8;
    using clickhouse::ExternalTables;

    // ---- Connection parameters ----
    const std::string host     = "clickhouse.liveaction.com";
    const int port             = 9440;  // native TLS port (commonly 9440)
    const std::string user     = "default";
    const std::string password = "clickhouse";

    // Path to the CA certificate (or CA bundle) that signed the server cert.
    const std::string ca_pem = "/home/mandrews/clickhouse-pinned-ca-bundle.pem";

    // Optional: for mutual TLS (mTLS). Leave empty if not required.
    const std::string_view client_cert_file = use_mtls ? "../../../../ch-client-ca/ch_client_ca.crt" : "";
    const std::string_view client_key_file  = use_mtls ? "../../../../ch-client-ca/ch_client_ca.key" : "";

    try {
        // Initialize OpenSSL (safe even on newer OpenSSL where it's mostly no-op)
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        using CtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
        CtxPtr ctx(SSL_CTX_new(TLS_client_method()), &SSL_CTX_free);
        if (!ctx) {
            throw std::runtime_error("SSL_CTX_new failed: " + OpenSSLErrorString());
        }

        // Enforce verification of the server certificate
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

        // Load CA used to verify the server certificate
        if (SSL_CTX_load_verify_locations(ctx.get(), ca_pem.c_str(), nullptr) != 1) {
            throw std::runtime_error("SSL_CTX_load_verify_locations failed: " + OpenSSLErrorString());
        }

        if constexpr (use_mtls) {
            // Load client cert/key for mTLS
            if (SSL_CTX_use_certificate_file(ctx.get(), client_cert_file.data(), SSL_FILETYPE_PEM) != 1) {
                throw std::runtime_error("SSL_CTX_use_certificate_file failed: " + OpenSSLErrorString());
            }

            if (SSL_CTX_use_PrivateKey_file(ctx.get(), client_key_file.data(), SSL_FILETYPE_PEM) != 1) {
                throw std::runtime_error("SSL_CTX_use_PrivateKey_file failed: " + OpenSSLErrorString());
            }

            if (SSL_CTX_check_private_key(ctx.get()) != 1) {
                throw std::runtime_error("SSL_CTX_check_private_key failed: " + OpenSSLErrorString());
            }
        }

        // Build ClickHouse options
        ClientOptions opts;
        opts.SetHost(host).SetPort(port).SetUser(user).SetPassword(password);

        // ---- Enable TLS and specify CA cert manually ----
        ClientOptions::SSLOptions ssl;

        // Important: if you use an external SSL_CTX, prefer not to also set CA files
        // in SSLOptions (to avoid ambiguity). Put trust material in the SSL_CTX (above).
        ssl.SetUseDefaultCALocations(false);

        // Attach the external context (this is the key fix for your version)
        ssl.SetExternalSSLContext(ctx.get());

        opts.SetSSLOptions(ssl);

        // ---- Create client and run a simple query ----
        Client client(opts);

        client.Execute("CREATE TABLE IF NOT EXISTS default.numbers (id UInt64, name String, saddr Nullable(IPv6)) ENGINE = Memory");

        /// Insert some values.
        {
            Block block;

            auto id   = std::make_shared<ColumnUInt64>();
            auto name = std::make_shared<ColumnString>();

            // nullable
            auto saddr_data = std::make_shared<ColumnIPv6>();
            auto saddr_null = std::make_shared<ColumnUInt8>();

            // pre-allocate column space
            id->Reserve(5);
            name->Reserve(5);
            saddr_data->Reserve(5);
            saddr_null->Reserve(5);

            // row 1
            id->Append(1);
            name->Append("one");
            AppendNullableIPv6(*saddr_data, *saddr_null, ip_2001_db8__1);

            // row 2
            id->Append(4);
            name->Append("four");
            AppendNullableIPv6(*saddr_data, *saddr_null, std::nullopt);

            // row 3
            id->Append(7);
            name->Append("seven");
            AppendNullableIPv6(*saddr_data, *saddr_null, IPv4Mapped(0x01020304));

            auto saddr = std::make_shared<ColumnNullable>(saddr_data, saddr_null);

            block.AppendColumn("id", id);
            block.AppendColumn("name", name);
            block.AppendColumn("saddr", saddr);

            client.Execute("TRUNCATE TABLE default.numbers");

            client.Insert("default.numbers", block);

            std::cout << "after 3 rows added capacity = " << id->Capacity() << " size = " << block.GetRowCount() << std::endl;
            block.Clear();
            std::cout << "after Clear() capacity = " << id->Capacity() << " size = " << block.GetRowCount() << std::endl;
        }

        /// Select values inserted in the previous step.
        std::ostringstream os;

        client.Select("SELECT id, name, saddr FROM default.numbers", [&](const Block& block) {
            // ignore the final empty/end block (0 columns / 0 rows).
            if (block.GetColumnCount() == 0 || block.GetRowCount() == 0) {
                return;
            }
            auto id_col   = block[0]->As<ColumnUInt64>();
            auto name_col = block[1]->As<ColumnString>();

            auto saddr_nullable = block[2]->As<ColumnNullable>();
            auto saddr_data     = saddr_nullable->Nested()->As<ColumnIPv6>();  // nested IPv6 values

            for (size_t i = 0; i < block.GetRowCount(); ++i) {
                os.str(std::string{});
                os.clear();  // clear fail/eof flags

                os << id_col->At(i) << " " << name_col->At(i) << " ";

                if (saddr_nullable->IsNull(i)) {
                    os << "NULL";
                    std::cout << os.str() << std::endl;
                    continue;
                }

                // ColumnIPv6::At(i) yields a 16-byte value (library-defined type; treat as raw bytes).
                const auto v = saddr_data->At(i);

                in6_addr a{};
                static_assert(sizeof(a) == 16, "Unexpected in6_addr size");
                std::memcpy(&a, &v, 16);

                char buf[INET6_ADDRSTRLEN] = {};
                if (!inet_ntop(AF_INET6, &a, buf, sizeof(buf))) {
                    os << "<invalid>";
                } else {
                    os << buf;
                }
                std::cout << os.str() << std::endl;
            }
        });

        /// Delete table.
        client.Execute("DROP TABLE default.numbers");

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "ClickHouse error: " << e.what() << "\n";
        return 1;
    }
}
