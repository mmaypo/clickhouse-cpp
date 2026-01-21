// app.cpp
#include "clickhouse/client.h"

#include "openssl/ssl.h"
#include "openssl/err.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

constexpr const bool use_mtls = true;

static std::string OpenSSLErrorString() {
    unsigned long err = ERR_get_error();
    if (err == 0) return {};
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

int main() {
    using clickhouse::Client;
    using clickhouse::ClientOptions;
    using clickhouse::Block;
    using clickhouse::ColumnUInt64;
    using clickhouse::ColumnString;
    using clickhouse::ExternalTables;


    // ---- Connection parameters ----
    const std::string host     = "clickhouse.liveaction.com";
    const int         port     = 9440;                // native TLS port (commonly 9440)
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

        if constexpr(use_mtls)
        {
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
        opts.SetHost(host)
            .SetPort(port)
            .SetUser(user)
            .SetPassword(password);

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

        client.Execute("CREATE TABLE IF NOT EXISTS default.numbers (id UInt64, name String) ENGINE = Memory");

        /// Insert some values.
        {
            Block block;

            auto id = std::make_shared<ColumnUInt64>();
            id->Append(1);
            id->Append(7);

            auto name = std::make_shared<ColumnString>();
            name->Append("one");
            name->Append("seven");

            block.AppendColumn("id"  , id);
            block.AppendColumn("name", name);

            client.Insert("default.numbers", block);
        }

        /// Select values inserted in the previous step.
        client.Select("SELECT id, name FROM default.numbers", [] (const Block& block)
            {
                for (size_t i = 0; i < block.GetRowCount(); ++i) {
                    std::cout << block[0]->As<ColumnUInt64>()->At(i) << " "
                            << block[1]->As<ColumnString>()->At(i) << "\n";
                }
            }
        );

        /// Select values inserted in the previous step using external data feature
        /// See https://clickhouse.com/docs/engines/table-engines/special/external-data
        {
            Block block1, block2;
            auto id = std::make_shared<ColumnUInt64>();
            id->Append(1);
            block1.AppendColumn("id"  , id);

            auto name = std::make_shared<ColumnString>();
            name->Append("seven");
            block2.AppendColumn("name", name);

            const std::string _1 = "_1";
            const std::string _2 = "_2";

            const ExternalTables external = {{_1, block1}, {_2, block2}};
            client.SelectWithExternalData("SELECT id, name FROM default.numbers where id in (_1) or name in (_2)",
                                        external, [] (const Block& block)
                {
                    for (size_t i = 0; i < block.GetRowCount(); ++i) {
                        std::cout << block[0]->As<ColumnUInt64>()->At(i) << " "
                                << block[1]->As<ColumnString>()->At(i) << "\n";
                    }
                }
            );
        }

        /// Delete table.
        client.Execute("DROP TABLE default.numbers");

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "ClickHouse error: " << e.what() << "\n";
        return 1;
    }
}
