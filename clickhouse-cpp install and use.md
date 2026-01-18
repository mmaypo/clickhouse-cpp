<!-- Start Document Outline -->

* [Installation of clickhouse-cpp library](#installation-of-clickhouse-cpp-library)
	* [Windows (VS 2026)](#windows-vs-2026)
	* [Linux](#linux)
* [Proof of Concept code using clickhouse-cpp and CMake](#proof-of-concept-code-using-clickhouse-cpp-and-cmake)
	* [1. Prerequisites](#1-prerequisites)
	* [2. Configure CMakeLists.txt](#2-configure-cmakeliststxt)
	* [3. Verification Code](#3-verification-code)
	* [4. Build Instructions](#4-build-instructions)
* [Setup TLS](#setup-tls)
	* [1. Update Clickhouse Server configuration](#1-update-clickhouse-server-configuration)
	* [2. Verification Code](#2-verification-code)
* [Setup mTLS using Client Certs](#setup-mtls-using-client-certs)
	* [1) Create a dedicated Client CA (one-time)](#1-create-a-dedicated-client-ca-one-time)
	* [2) Issue a client cert per service](#2-issue-a-client-cert-per-service)
	* [3) Configure ClickHouse server to require client certs (mTLS)](#3-configure-clickhouse-server-to-require-client-certs-mtls)
	* [4) Map service cert identity to a ClickHouse user](#4-map-service-cert-identity-to-a-clickhouse-user)
	* [5) Client side (your service)](#5-client-side-your-service)
	* [Changes to clickhouse-server config.xml](#changes-to-clickhouse-server-configxml)
		* [Next steps checklist (commands)](#next-steps-checklist-commands)
	* [OpenSSL CSR/signing commands and the corresponding ClickHouse users.d mapping for SAN URI](#openssl-csrsigning-commands-and-the-corresponding-clickhouse-usersd-mapping-for-san-uri)
		* [Target standard (services, SAN URI)](#target-standard-services-san-uri)
		* [1) Issue a client cert with SAN URI (OpenSSL)](#1-issue-a-client-cert-with-san-uri-openssl)
		* [2) Configure ClickHouse to require client certs (mTLS)](#2-configure-clickhouse-to-require-client-certs-mtls)
		* [3) Map SAN URI to a ClickHouse user](#3-map-san-uri-to-a-clickhouse-user)
		* [4) Client-side (your clickhouse-cpp/OpenSSL client)](#4-client-side-your-clickhouse-cppopenssl-client)
	* [template script to issue/revoke/rotate certs](#template-script-to-issuerevokerotate-certs)
		* [What you deploy to ClickHouse](#what-you-deploy-to-clickhouse)
		* [Client-side: clickhouse-cpp + OpenSSL (present client cert + key)](#client-side-clickhouse-cpp--openssl-present-client-cert--key)
			* [Important: user mapping for SAN URI](#important-user-mapping-for-san-uri)
			* [Common failure modes (and what the error will look like)](#common-failure-modes-and-what-the-error-will-look-like)

<!-- End Document Outline -->

# Installation of clickhouse-cpp library

<!-- TOC --><a name="windows-vs-2026"></a>
## Windows (VS 2026)

> set OPENSSL_ROOT_DIR=D:\dev\working\github\livewire\third-party\openssl
mkdir build . 
cd build  
cmake .. -DBUILD_BENCHMARK=ON -DWITH_OPENSSL=ON -DDEBUG_DEPENDENCIES=ON
make


To ensure a successful link, ensure the following are added to your project's Additional Dependencies:
```
clickhouse-cpp-lib.lib
cityhash.lib
lz4.lib
(All required absl_*.lib files produced during your build)
ws2_32.lib
crypt32.lib
libssl.lib and libcrypto.lib  from third-party\openssl
```

## Linux

**TODO**

# Proof of Concept code using clickhouse-cpp and CMake

## 1. Prerequisites
- **Visual Studio 2026**: Ensure the "Desktop development with C++" workload is installed. This includes the **v14.50 toolset**.
- **CMake**: Visual Studio 2026 includes CMake 4.1+ by default, which is fully compatible.
- **Git**: Must be installed and available in your PATH for `FetchContent` to download the source.

## 2. Configure CMakeLists.txt
Create a `CMakeLists.txt` in your project root. This configuration uses `FetchContent` to download `clickhouse-cpp` v2.6.0 and its core dependencies (Abseil, LZ4, CityHash) automatically.

```cmake
cmake_minimum_required(VERSION 3.14)
project(ClickHouseApp)

# 1. Enable C++17 (Required by clickhouse-cpp)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 2. Configuration Options
set(WITH_OPENSSL OFF CACHE BOOL "Enable OpenSSL support" FORCE)

# 3. Fetch the library
include(FetchContent)
FetchContent_Declare(
    clickhouse-cpp
    GIT_REPOSITORY https://github.com/ClickHouse/clickhouse-cpp.git
    GIT_TAG v2.6.0
)
FetchContent_MakeAvailable(clickhouse-cpp)

# 4. Define your executable
add_executable(ClickHouseApp main.cpp)

# 5. Link clickhouse-cpp and mandatory Windows libraries
target_link_libraries(ClickHouseApp 
    PRIVATE 
    clickhouse-cpp-lib
    ws2_32        # Windows Sockets
    crypt32       # Windows Cryptography
)
```

## 3. Verification Code
Create a `main.cpp` file in the same directory. Note that as of v2.6.0, the library uses `absl::uint128` for consistency across platforms.

```cpp
#include <clickhouse/client.h>
#include <iostream>

int main() {
    try {
        // Connect to a local instance
        clickhouse::Client client(clickhouse::ClientOptions().SetHost("localhost"));

        // Test connectivity
        client.Execute("SELECT 1", [](const clickhouse::Block& block) {
            for (size_t i = 0; i < block.GetRowCount(); ++i) {
                std::cout << "Successfully read row " << i << " from ClickHouse." << std::endl;
            }
        });

        std::cout << "Connection and query successful!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
```

## 4. Build Instructions
1. **Open Folder**: Launch Visual Studio 2026 and select **File > Open > Folder...**. Choose the directory containing your files.
2. **Configure**: Visual Studio will detect the `CMakeLists.txt` and automatically run the CMake generation. Wait for "CMake generation finished" in the **Output window**.
3. **Build**: Go to **Build > Build All** (or press `Ctrl + Shift + B`).
4. **Run**: Change the Startup Item in the top toolbar to `ClickHouseApp.exe` and press **F5** to run.


# Setup TLS  

The previous section showed how to setup a POC code example with no TLS, this section shows changes needed to implement TLS with server certificate.  

## 1. Update Clickhouse Server configuration

modify **/etc/clickhouse-server/config.xml** to enable \<tcp_port\>, \<https_port\>, \<certificateFile\>, and \<privateKeyFile\>:  

```bash
root@ubuntu24srvr2:/etc/clickhouse-server# diff config.xml.NO-TLS config.xml.TLS 
206c206
<     <!-- <https_port>8443</https_port> -->
---
>     <https_port>8443</https_port>
212c212
<     <!-- <tcp_port_secure>9440</tcp_port_secure> -->
---
>     <tcp_port_secure>9440</tcp_port_secure>
357,358c357,358
<             <!-- <certificateFile>/etc/clickhouse-server/server.crt</certificateFile>
<             <privateKeyFile>/etc/clickhouse-server/server.key</privateKeyFile> -->
---
>             <certificateFile>/etc/clickhouse-server/star_liveaction_com.pem</certificateFile>
>             <privateKeyFile>/etc/clickhouse-server/star_liveaction_com.key</privateKeyFile>
```

## 2. Verification Code

```cpp
#include "clickhouse/client.h"

#include "openssl/ssl.h"
#include "openssl/err.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

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


    // ---- Connection parameters (adjust to your environment) ----
    const std::string host     = "clickhouse.liveaction.com";
    const int         port     = 9440;                // native TLS port (commonly 9440)
    const std::string user     = "default";
    const std::string password = "clickhouse";

    // Path to the CA certificate (or CA bundle) that signed the server cert.
    const std::string ca_pem = "/home/mandrews/clickhouse-pinned-ca-bundle.pem";     

    // Optional: for mutual TLS (mTLS). Leave empty if not required.
    const std::string client_cert_file = "";
    const std::string client_key_file  = "";

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
```


# Setup mTLS using Client Certs

The previous section showed how to setup a POC code example with TLS, this section shows a service-oriented way to generate client certificates and configure ClickHouse to require them (mTLS), using your own “client CA” to issue per-service certs.

## 1) Create a dedicated Client CA (one-time)  

Do this on a secure workstation (not necessarily the ClickHouse server). This CA signs client certs.

```
mkdir -p ~/ch-client-ca && cd ~/ch-client-ca
chmod 700 .

# CA private key (keep this secure)
openssl genrsa -out ch_client_ca.key 4096
chmod 600 ch_client_ca.key

# CA certificate (public)
openssl req -x509 -new -nodes -key ch_client_ca.key -sha256 -days 3650 \
  -subj "/C=US/ST=CA/O=BlueCat/CN=ClickHouse Client CA" \
  -out ch_client_ca.crt
chmod 644 ch_client_ca.crt
```  

This aligns with ClickHouse’s recommended “self-signed CA for testing / internal PKI” workflow  

<br>

## 2) Issue a client cert per service 

**Pick an identity scheme to map into clickhouse**  

* Use SAN URI (recommended for services) when you want a structured, unambiguous identity (e.g., spiffe://…), and you may have many services across environments.
* Use SAN DNS when your services already have stable DNS names you can manage (e.g., svc-ingest.prod.bluecatnetworks.com).
* Use CN only for legacy compatibility; CN is less expressive and can be ambiguous, and many modern PKI practices treat SAN as the primary identity.  

<br> 

We will use SAN URI. Example: service svc_livewire:  

```
SERVICE="svc_livewire"

# private key
openssl genrsa -out "${SERVICE}.key" 2048
chmod 600 "${SERVICE}.key"

# CSR with SAN (URI + DNS examples; keep what you need)
openssl req -new -key "${SERVICE}.key" \
  -subj "/CN=${SERVICE}" \
  -out "${SERVICE}.csr" \
  -addext "subjectAltName = URI:spiffe://bluecatnetworks.com/clickhouse/${SERVICE},DNS:${SERVICE}.bluecatnetworks.com" \
  -addext "extendedKeyUsage = clientAuth"

```

<br> 

Sign it with your client CA:  

```bash
openssl x509 -req -in "${SERVICE}.csr" \
  -CA ch_client_ca.crt -CAkey ch_client_ca.key -CAcreateserial \
  -out "${SERVICE}.crt" -days 825 -sha256
chmod 644 "${SERVICE}.crt"

```

Artifacts to distribute to the service:

* $\{SERVICE\}.crt (client cert)  
* $\{SERVICE\}.key (client private key)  

<br>

## 3) Configure ClickHouse server to require client certs (mTLS)  

Copy the client CA cert (NOT the CA private key) onto the ClickHouse server:  
> sudo install -m 0644 ch_client_ca.crt /etc/clickhouse-server/ch_client_ca.crt  

Then enable secure port and set OpenSSL server verification to strict and point it at your CA file via caConfig. strict is the setting ClickHouse documents as enforcing mandatory certificate validation for incoming connections.

Create /etc/clickhouse-server/config.d/mtls.xml:  

```xml
<clickhouse>
  <tcp_port_secure>9440</tcp_port_secure>

  <openSSL>
    <server>
      <certificateFile>/etc/clickhouse-server/server.crt</certificateFile>
      <privateKeyFile>/etc/clickhouse-server/server.key</privateKeyFile>

      <!-- Require and validate client certificates -->
      <verificationMode>strict</verificationMode>
      <caConfig>/etc/clickhouse-server/ch_client_ca.crt</caConfig>
    </server>
  </openSSL>
</clickhouse>

```

Operationally, if you require client certs, ensure clients can’t bypass mTLS by connecting to plain tcp_port (9000). Many teams simply firewall/disable the insecure port.

Restart:  
> sudo systemctl restart clickhouse-server  

<br>

## 4) Map service cert identity to a ClickHouse user

**About UR:spiffe://**  

spiffe://… is a URI format defined by SPIFFE (Secure Production Identity Framework for Everyone). It is used to represent a workload/service identity as a stable, structured identifier, independent of IPs and often independent of DNS.

What “URI:spiffe://…” means in a certificate

In an X.509 certificate, identities are normally carried in the Subject Alternative Name (SAN) extension. One SAN type is a URI. When you see:

URI:spiffe://bluecatnetworks.com/clickhouse/prod/svc_livewire

that means the certificate’s SAN contains a URI value, and the URI scheme is spiffe.

**Why it’s useful for services**

Using a SPIFFE-style URI as the canonical identity gives you:

* Uniqueness and structure (domain + path)
* Environment scoping (/prod/, /dev/, etc.)
* No dependence on DNS or IP
* A clean mapping for authorization (e.g., “only this service identity can authenticate as this ClickHouse user”)

You can match on either CN or SAN. The ClickHouse docs show both, via users.xml/users.d (<ssl_certificates>…</ssl_certificates>) and via SQL IDENTIFIED WITH ssl_certificate.

File-based (users.d) example (SAN URI)

Create /etc/clickhouse-server/users.d/svc_livewire.xml:  

```xml
<clickhouse>
  <users>
    <svc_livewire>
      <ssl_certificates>
        <subject_alt_name>URI:spiffe://bluecatnetworks.com/clickhouse/svc_livewire</subject_alt_name>
      </ssl_certificates>
      <!-- set grants/roles/etc here -->
    </svc_livewire>
  </users>
</clickhouse>
```

(You can also use <common_name>...</common_name> entries if you prefer CN-based identity.)

<br>

## 5) Client side (your service)

Provide the client cert/key to your client TLS context (OpenSSL), and keep your server-trust file logic as you already have.
i.e., the C++ client app has to do two separate TLS things:

1. Prove its own identity to the server (client authentication)

This means: load a client certificate and its private key into the OpenSSL context you give to clickhouse-cpp. During the TLS handshake, the server (ClickHouse) will request a client certificate because we set verificationMode=strict. If the client does not present one, the handshake fails.

In OpenSSL terms, these calls enable that:  

```cpp
SSL_CTX_use_certificate_file(ctx.get(), client_cert_path, SSL_FILETYPE_PEM);
SSL_CTX_use_PrivateKey_file(ctx.get(), client_key_path, SSL_FILETYPE_PEM);
SSL_CTX_check_private_key(ctx.get());
```

2. Verify the server’s identity (server authentication)  
 
the client needs to verify the server certificate is legitimate. That is the normal TLS “don’t talk to an impostor” check.

In OpenSSL terms, that is:

```cpp
SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
SSL_CTX_load_verify_locations(ctx.get(), server_ca_bundle_path, nullptr);
```

Where **server_ca_bundle_path** is the file you use to trust the server certificate chain. In your case you were already loading trust from a file (either:

* /etc/ssl/certs/ca-certificates.crt (system roots), or
* your pinned bundle file like /home/mandrews/clickhouse-pinned-ca-bundle.pem).

Effect:

The client checks the ClickHouse server’s presented cert chains to a trusted CA in that file (DigiCert chain in our case).

If you use a pinned bundle you control, this trust stays stable even if the OS CA store changes.

<br>

## Changes to clickhouse-server config.xml

To require client certificates (mTLS) on the secure TCP port / HTTPS, you only need to change two things in the existing plain (non-mTLS) <openSSL><server> block:

switch verification from none to strict (so the server requires and validates client certs)

tell the server which CA(s) are allowed to sign client certs via caConfig

**Minimal mTLS change to your snippet**

Create a client CA cert file (public CA cert only) on the ClickHouse server, e.g.:
/etc/clickhouse-server/ch_client_ca.crt

Why set loadDefaultCAFile to false on the server? For mTLS, you typically want to accept only certs chained to your internal client CA, not any public CA in the OS bundle. Setting loadDefaultCAFile=false makes the trust boundary explicit.

**Operational notes**

This change enforces client certs on all TLS listeners using this <server> context (secure native TCP and HTTPS, as your comment notes). If you want mTLS only on one interface and not the other, you’ll need separate TLS contexts (more involved).

You still need to map the client cert to a ClickHouse user (CN/SAN mapping) in users.d/*.xml or via SQL auth, otherwise the TLS handshake may succeed but the user may still not be authorized as intended.

<br>

### Next steps checklist (commands)

1 Place your client CA cert on the server:  
> sudo install -m 0644 ch_client_ca.crt /etc/clickhouse-server/ch_client_ca.crt

2 Restart  
> sudo systemctl restart clickhouse-server  

3 Verify that clients without a cert are rejected:

> openssl s_client -connect clickhouse.bluecatnetworks.com:9440 -servername clickhouse.bluecatnetworks.com </dev/null  

This should fail once verificationMode is strict (because no client cert is presented).

<br>

## OpenSSL CSR/signing commands and the corresponding ClickHouse users.d mapping for SAN URI   

### Target standard (services, SAN URI)

Recommendation is to Issue client certs with:

* CN=\<service-name\> (for readability)  
* SAN URI=spiffe://bluecatnetworks.com/clickhouse/\<env\>/\<service-name\> (for authentication)  
* optionally SAN DNS=\<service\>.\<env\>.bluecatnetworks.com (if useful)  

So, set CN to something readable (e.g., svc_livewire), but ClickHouse auth will key off the SAN URI. Use a URI identity like:

* spiffe://bluecatnetworks.com/clickhouse/\<env\>/\<service\>

Example:

* spiffe://bluecatnetworks.com/clickhouse/prod/svc_livewire

<br>

### 1) Issue a client cert with SAN URI (OpenSSL)

On your CA host (where ch_client_ca.key and ch_client_ca.crt live):

```bash
ENV="prod"
SERVICE="svc_livewire"
URI="spiffe://bluecatnetworks.com/clickhouse/${ENV}/${SERVICE}"

# Key
openssl genrsa -out "${SERVICE}.key" 2048
chmod 600 "${SERVICE}.key"

# CSR with SAN URI
openssl req -new -key "${SERVICE}.key" \
  -subj "/CN=${SERVICE}" \
  -out "${SERVICE}.csr" \
  -addext "subjectAltName = URI:${URI}" \
  -addext "extendedKeyUsage = clientAuth"
```

Sign it with your client CA:  

```
openssl x509 -req -in "${SERVICE}.csr" \
  -CA ch_client_ca.crt -CAkey ch_client_ca.key -CAcreateserial \
  -out "${SERVICE}.crt" -days 825 -sha256
chmod 644 "${SERVICE}.crt"

```

Verify the SAN URI is present:

> openssl x509 -in "${SERVICE}.crt" -noout -subject -ext subjectAltName


You should see URI:spiffe://bluecatnetworks.com/clickhouse/prod/svc_livewire.

<br>

### 2) Configure ClickHouse to require client certs (mTLS)

You already have server TLS working. To require client certs and trust only your client CA, set:

<verificationMode>strict</verificationMode>

<caConfig>/etc/clickhouse-server/ch_client_ca.crt</caConfig>

and typically <loadDefaultCAFile>false</loadDefaultCAFile>

(Using the snippet you already have, just add/adjust those lines.)

Restart ClickHouse after changes.

<br>

### 3) Map SAN URI to a ClickHouse user

**Create /etc/clickhouse-server/users.d/svc_livewire.xml:**

```xml
<clickhouse>
  <users>
    <svc_livewire>
      <ssl_certificates>
        <subject_alt_name>URI:spiffe://bluecatnetworks.com/clickhouse/prod/svc_livewire</subject_alt_name>
      </ssl_certificates>

      <!-- Example: lock down network access, roles, etc. -->
      <!-- <networks><ip>::/0</ip></networks> -->
    </svc_livewire>
  </users>
</clickhouse>
```
Restart ClickHouse (or reload config if you have that enabled).  

<br>

### 4) Client-side (your clickhouse-cpp/OpenSSL client)

In your SSL_CTX setup, add:

```
SSL_CTX_use_certificate_file(ctx.get(), "/path/to/svc_livewire.crt", SSL_FILETYPE_PEM);
SSL_CTX_use_PrivateKey_file(ctx.get(), "/path/to/svc_livewire.key", SSL_FILETYPE_PEM);
SSL_CTX_check_private_key(ctx.get());
```

And keep server verification using a CA file/bundle as you already do.


<br>

## template script to issue/revoke/rotate certs 

```
#!/usr/bin/env bash
# ch_mtls_ca_db.sh
#
# CA-database-backed mTLS client certificate management for ClickHouse services.
#
# Standards enforced:
#   - env ∈ {dev, stage, prod}
#   - service name begins with "svc_"
#   - SAN URI = spiffe://bluecatnetworks.com/clickhouse/<env>/<service>
#
# Provides:
#   - init-ca : initialize CA directory + OpenSSL CA database, create CA key/cert
#   - issue   : issue a client cert/key for a service (tracked in CA DB)
#   - revoke  : revoke a previously issued cert (updates CA DB + generates CRL)
#   - rotate  : revoke old cert (optional) and issue a new one
#   - crl     : generate CRL
#   - list    : list issued certs (from filesystem)
#   - show    : show subject/SAN of a cert
#   - ca-db   : show CA DB entries (index.txt)
#
# Layout:
#   ./ca/
#     openssl.cnf
#     private/ca.key.pem
#     certs/ca.crt.pem
#     db/index.txt db/index.txt.attr db/serial db/crlnumber
#     newcerts/ (OpenSSL CA stores issued cert copies here)
#     crl/ca.crl.pem
#   ./issued/<env>/<service>/
#     client.key.pem
#     client.csr.pem
#     client.crt.pem
#     client.fullchain.pem
#     meta.txt
#     archive/<timestamp>/...
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$SCRIPT_DIR}"
CA_DIR="${CA_DIR:-$BASE_DIR/ca}"
ISSUED_DIR="${ISSUED_DIR:-$BASE_DIR/issued}"

DOMAIN="${DOMAIN:-bluecatnetworks.com}"
SPIFFE_TRUST_DOMAIN="${SPIFFE_TRUST_DOMAIN:-$DOMAIN}"
SPIFFE_PREFIX="${SPIFFE_PREFIX:-spiffe://${SPIFFE_TRUST_DOMAIN}/clickhouse}"

CA_DAYS="${CA_DAYS:-3650}"          # 10 years
CLIENT_DAYS="${CLIENT_DAYS:-365}"   # 1 year
CRL_DAYS="${CRL_DAYS:-30}"          # CRL validity

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

err()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "INFO: $*" >&2; }

require_env() {
  local env="$1"
  case "$env" in dev|stage|prod) ;; *) err "env must be dev|stage|prod (got: $env)";; esac
}

require_service() {
  local svc="$1"
  [[ "$svc" == svc_* ]] || err "service must start with svc_ (got: $svc)"
  [[ "$svc" =~ ^[A-Za-z0-9_]+$ ]] || err "service must be alnum/underscore only (got: $svc)"
}

ca_paths() {
  CA_CONF="$CA_DIR/openssl.cnf"
  CA_KEY="$CA_DIR/private/ca.key.pem"
  CA_CERT="$CA_DIR/certs/ca.crt.pem"
  CA_CRL="$CA_DIR/crl/ca.crl.pem"
  CA_INDEX="$CA_DIR/db/index.txt"
}

make_ca_conf() {
  ca_paths
  cat > "$CA_CONF" <<EOF
# OpenSSL CA configuration for ClickHouse mTLS client certificates

[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $CA_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/db/index.txt
serial            = \$dir/db/serial
crlnumber         = \$dir/db/crlnumber
RANDFILE          = \$dir/private/.rand

private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.crt.pem

crl               = \$dir/crl/ca.crl.pem
default_crl_days  = $CRL_DAYS
crl_extensions    = crl_ext

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = $CLIENT_DAYS
preserve          = no
policy            = policy_loose

# Allow multiple active certs for same subject (helps rotation)
unique_subject    = no

# IMPORTANT: copy SAN/other requested extensions from CSR into the issued cert
copy_extensions   = copy

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
distinguished_name  = req_dn
req_extensions      = req_ext

[ req_dn ]
CN = placeholder

[ req_ext ]
# CSR extensions are set via "openssl req -addext ..."

[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage         = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ v3_client ]
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = critical, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
# SAN comes from CSR due to copy_extensions=copy

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF
}

init_ca() {
  ca_paths
  info "Initializing CA directory: $CA_DIR"
  mkdir -p "$CA_DIR"/{certs,crl,newcerts,private,db}
  chmod 700 "$CA_DIR/private"

  # CA database files
  [[ -f "$CA_DIR/db/index.txt" ]] || : > "$CA_DIR/db/index.txt"
  [[ -f "$CA_DIR/db/index.txt.attr" ]] || echo "unique_subject = no" > "$CA_DIR/db/index.txt.attr"
  [[ -f "$CA_DIR/db/serial" ]] || echo "1000" > "$CA_DIR/db/serial"
  [[ -f "$CA_DIR/db/crlnumber" ]] || echo "1000" > "$CA_DIR/db/crlnumber"

  make_ca_conf

  if [[ -f "$CA_KEY" && -f "$CA_CERT" ]]; then
    info "CA key/cert already exist; skipping creation."
  else
    info "Generating CA key: $CA_KEY"
    "$OPENSSL_BIN" genrsa -out "$CA_KEY" 4096
    chmod 600 "$CA_KEY"

    info "Generating self-signed CA cert: $CA_CERT"
    "$OPENSSL_BIN" req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$CA_DAYS" \
      -subj "/C=US/ST=CA/O=LiveAction/CN=ClickHouse Client CA" \
      -out "$CA_CERT"
    chmod 644 "$CA_CERT"
  fi

  info "Generating initial CRL: $CA_CRL"
  "$OPENSSL_BIN" ca -config "$CA_CONF" -gencrl -out "$CA_CRL" -batch >/dev/null 2>&1 || true
  [[ -f "$CA_CRL" ]] && chmod 644 "$CA_CRL" || true

  info "Done."
  info "  CA cert: $CA_CERT"
  info "  CA CRL : $CA_CRL"
}

gen_crl() {
  ca_paths
  [[ -f "$CA_CONF" ]] || err "CA not initialized. Run: $0 init-ca"
  info "Generating CRL..."
  "$OPENSSL_BIN" ca -config "$CA_CONF" -gencrl -out "$CA_CRL" -batch
  chmod 644 "$CA_CRL"
  info "CRL written: $CA_CRL"
}

issue() {
  local env="$1" svc="$2"
  require_env "$env"
  require_service "$svc"
  ca_paths

  [[ -f "$CA_KEY" && -f "$CA_CERT" && -f "$CA_CONF" ]] || err "CA not initialized. Run: $0 init-ca"

  local outdir="$ISSUED_DIR/$env/$svc"
  mkdir -p "$outdir"
  chmod 700 "$outdir" || true

  local key="$outdir/client.key.pem"
  local csr="$outdir/client.csr.pem"
  local crt="$outdir/client.crt.pem"
  local fullchain="$outdir/client.fullchain.pem"
  local meta="$outdir/meta.txt"

  local uri="${SPIFFE_PREFIX}/${env}/${svc}"

  info "Issuing client cert (CA-DB tracked) for env=$env service=$svc"
  info "  SAN URI: $uri"

  # Always generate a fresh key unless caller wants to keep it.
  # If you prefer to keep keys stable across rotation, comment out the rm line.
  rm -f "$key" "$csr" "$crt" "$fullchain" "$meta" 2>/dev/null || true

  "$OPENSSL_BIN" genrsa -out "$key" 2048
  chmod 600 "$key"

  # Create CSR with SAN URI and EKU=clientAuth
  "$OPENSSL_BIN" req -new -key "$key" \
    -subj "/CN=${svc}" \
    -out "$csr" \
    -addext "subjectAltName = URI:${uri}" \
    -addext "extendedKeyUsage = clientAuth"

  # Sign using openssl ca so the cert is recorded in CA DB (index.txt)
  "$OPENSSL_BIN" ca -config "$CA_CONF" \
    -extensions v3_client \
    -in "$csr" -out "$crt" \
    -notext -md sha256 -batch

  chmod 644 "$crt"
  cat "$crt" "$CA_CERT" > "$fullchain"
  chmod 644 "$fullchain"

  {
    echo "env=$env"
    echo "service=$svc"
    echo "uri=$uri"
    echo "issued_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "expires_at_utc=$("$OPENSSL_BIN" x509 -in "$crt" -noout -enddate | cut -d= -f2)"
    echo "serial=$("$OPENSSL_BIN" x509 -in "$crt" -noout -serial | cut -d= -f2)"
  } > "$meta"
  chmod 644 "$meta"

  info "Issued:"
  info "  key       : $key"
  info "  cert      : $crt"
  info "  fullchain : $fullchain"
  info "  meta      : $meta"
}

revoke() {
  local cert_path="$1"
  ca_paths
  [[ -f "$CA_CONF" ]] || err "CA not initialized. Run: $0 init-ca"
  [[ -f "$cert_path" ]] || err "cert not found: $cert_path"

  info "Revoking cert (tracked in CA DB): $cert_path"
  "$OPENSSL_BIN" ca -config "$CA_CONF" -revoke "$cert_path" -batch
  gen_crl
}

rotate() {
  local env="$1" svc="$2"
  shift 2
  local keep_old="false"
  if [[ "${1:-}" == "--keep-old" ]]; then
    keep_old="true"
  fi

  require_env "$env"
  require_service "$svc"

  local outdir="$ISSUED_DIR/$env/$svc"
  local crt="$outdir/client.crt.pem"

  if [[ -f "$crt" && "$keep_old" == "false" ]]; then
    revoke "$crt"
  fi

  # Archive old artifacts if present
  if [[ -d "$outdir" ]]; then
    local ts
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$outdir/archive/$ts"
    for f in client.key.pem client.csr.pem client.crt.pem client.fullchain.pem meta.txt; do
      [[ -f "$outdir/$f" ]] && mv "$outdir/$f" "$outdir/archive/$ts/" || true
    done
  fi

  issue "$env" "$svc"
}

list_issued() {
  find "$ISSUED_DIR" -name 'client.crt.pem' -print 2>/dev/null | sort
}

show_cert() {
  local cert_path="$1"
  [[ -f "$cert_path" ]] || err "cert not found: $cert_path"
  "$OPENSSL_BIN" x509 -in "$cert_path" -noout -subject -issuer -dates -serial
  "$OPENSSL_BIN" x509 -in "$cert_path" -noout -ext subjectAltName || true
}

show_ca_db() {
  ca_paths
  [[ -f "$CA_INDEX" ]] || err "CA not initialized. Run: $0 init-ca"
  echo "== CA DB: $CA_INDEX =="
  # Format: V/R, expiration, revocation, serial, filename, subject
  sed -n '1,200p' "$CA_INDEX"
}

usage() {
  cat <<EOF
Usage:
  $0 init-ca
  $0 issue   <dev|stage|prod> <svc_name>
  $0 revoke  <path/to/client.crt.pem>
  $0 rotate  <dev|stage|prod> <svc_name> [--keep-old]
  $0 crl
  $0 list
  $0 show    <path/to/cert.pem>
  $0 ca-db

Environment:
  BASE_DIR, CA_DIR, ISSUED_DIR
  DOMAIN, SPIFFE_TRUST_DOMAIN, SPIFFE_PREFIX
  CA_DAYS, CLIENT_DAYS, CRL_DAYS
EOF
}

cmd="${1:-}"
shift || true

case "$cmd" in
  init-ca) init_ca ;;
  issue)
    [[ $# -eq 2 ]] || err "usage: $0 issue <dev|stage|prod> <svc_name>"
    issue "$1" "$2"
    ;;
  revoke)
    [[ $# -eq 1 ]] || err "usage: $0 revoke <path/to/client.crt.pem>"
    revoke "$1"
    ;;
  rotate)
    [[ $# -ge 2 ]] || err "usage: $0 rotate <dev|stage|prod> <svc_name> [--keep-old]"
    rotate "$@"
    ;;
  crl) gen_crl ;;
  list) list_issued ;;
  show)
    [[ $# -eq 1 ]] || err "usage: $0 show <path/to/cert.pem>"
    show_cert "$1"
    ;;
  ca-db) show_ca_db ;;
  *) usage; exit 1 ;;
esac
```

<br>

**Practical usage (example)**

```
./ch_mtls_ca_db.sh init-ca
./ch_mtls_ca_db.sh issue prod svc_livewire
./ch_mtls_ca_db.sh show issued/prod/svc_livewire/client.crt.pem
./ch_mtls_ca_db.sh rotate prod svc_livewire
./ch_mtls_ca_db.sh revoke issued/prod/svc_livewire/client.crt.pem
./ch_mtls_ca_db.sh crl
./ch_mtls_ca_db.sh ca-db
```

<br>

### What you deploy to ClickHouse

* Client CA certificate: ca/certs/ca.crt.pem (copy to /etc/clickhouse-server/ch_client_ca.crt)
* CRL (if you plan to enforce revocation): ca/crl/ca.crl.pem (optional; enforcement 
depends on your TLS stack/config)

**What to verify on the server**

1 The client-CA file is readable by the ClickHouse process:

> sudo -u clickhouse test -r /etc/clickhouse-server/ch_client_ca.crt && echo OK

2 mTLS is actually enforced (this should now fail because no client cert):

> openssl s_client -connect clickhouse.bluecatnetworks.com:9440 -servername clickhouse.bluecatnetworks.com </dev/null

3 With a client cert, it should succeed:  
```
openssl s_client -connect clickhouse.bluecatnetworks.com:9440 -servername clickhouse.bluecatnetworks.com \
  -cert issued/prod/svc_livewire/client.crt.pem \
  -key  issued/prod/svc_livewire/client.key.pem \
  </dev/null
```

### Client-side: clickhouse-cpp + OpenSSL (present client cert + key)

Below is the minimal, correct pattern for your version of clickhouse-cpp (the one that supports SetExternalSSLContext(SSL_CTX*)).

**Key points:**

* Use hostname, not IP (clickhouse.bluecatnetworks.com) so SNI/hostname checks work.
* Load the server trust from a file (your pinned CA bundle), per your constraint.
* Load client cert/key into the same SSL_CTX so the client presents them during handshake.
 
<br>

Example TLS client setup (mTLS):  

```cpp
#include "clickhouse/client.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

static std::string OpenSSLErrorString() {
    unsigned long err = ERR_get_error();
    if (err == 0) return {};
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

static void ThrowIf(bool ok, const std::string& msg) {
    if (!ok) throw std::runtime_error(msg + ": " + OpenSSLErrorString());
}

int main() {
    using clickhouse::Client;
    using clickhouse::ClientOptions;

    // ---- Connection parameters ----
    const std::string host = "clickhouse.bluecatnetworks.com"; // must match cert/SAN
    const int         port = 9440;                        // native secure port
    const std::string user = "svc_livewire";                // ClickHouse user you map to SAN URI
    const std::string password = "";                      // typically unused for ssl_certificate auth

    // ---- Server verification: file you control (pinning) ----
    // Option 1: system bundle file (stable path, but may change as OS updates)
    // const std::string server_ca_bundle = "/etc/ssl/certs/ca-certificates.crt";

    // Option 2: your pinned bundle file (recommended for "trust even if system roots change")
    const std::string server_ca_bundle = "/home/mandrews/clickhouse-pinned-ca-bundle.pem";

    // ---- Client identity (mTLS) ----
    const std::string client_cert = "/home/mandrews/issued/prod/svc_livewire/client.crt.pem";
    const std::string client_key  = "/home/mandrews/issued/prod/svc_livewire/client.key.pem";

    try {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        using CtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
        CtxPtr ctx(SSL_CTX_new(TLS_client_method()), &SSL_CTX_free);
        ThrowIf(ctx != nullptr, "SSL_CTX_new failed");

        // Require server verification
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

        // Load server trust from your file (pinning via CA bundle you control)
        ThrowIf(SSL_CTX_load_verify_locations(ctx.get(), server_ca_bundle.c_str(), nullptr) == 1,
                "SSL_CTX_load_verify_locations failed");

        // Load client cert/key for mTLS
        ThrowIf(SSL_CTX_use_certificate_file(ctx.get(), client_cert.c_str(), SSL_FILETYPE_PEM) == 1,
                "SSL_CTX_use_certificate_file failed");

        ThrowIf(SSL_CTX_use_PrivateKey_file(ctx.get(), client_key.c_str(), SSL_FILETYPE_PEM) == 1,
                "SSL_CTX_use_PrivateKey_file failed");

        ThrowIf(SSL_CTX_check_private_key(ctx.get()) == 1,
                "SSL_CTX_check_private_key failed");

        // (Recommended) Ensure OpenSSL verifies the server hostname (SNI/hostname)
        // clickhouse-cpp should set SNI based on host; hostname verification may still be needed at OpenSSL level.
        // If your build exposes hooks to set X509_VERIFY_PARAM, set it here; otherwise rely on CA + correct host.

        ClientOptions opts;
        opts.SetHost(host)
            .SetPort(port)
            .SetUser(user)
            .SetPassword(password);

        ClientOptions::SSLOptions ssl;
        ssl.SetUseDefaultCALocations(false);
        ssl.SetExternalSSLContext(ctx.get());
        opts.SetSSLOptions(ssl);

        Client client(opts);

        client.Select("SELECT 1", [](const clickhouse::Block& block) {
            std::cout << "Connected OK, rows=" << block.GetRowCount() << "\n";
        });

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "ClickHouse error: " << e.what() << "\n";
        return 1;
    }
}

```

<br>

#### Important: user mapping for SAN URI

Because you’re using SAN URI, make sure the ClickHouse user you set (svc_livewire) has an ssl_certificates rule matching the URI in the **/etc/clickhouse-server/users.d/svc_livewire.xml** file, e.g.:

```xml
<clickhouse>
  <users>
    <svc_ingest>
      <ssl_certificates>
        <subject_alt_name>URI:spiffe://liveaction.com/clickhouse/prod/svc_livewire</subject_alt_name>
      </ssl_certificates>

      <!-- Optional: define profile/quota/roles as needed -->
      <!-- <profile>default</profile> -->
      <!-- <quota>default</quota> -->
    </svc_ingest>
  </users>
</clickhouse>
```  

If you do not map it, the TLS handshake can succeed but authentication/authorization can still fail.  

<br>  

#### Common failure modes (and what the error will look like)

* No client cert presented → handshake fails (server side strict).
* Client cert not signed by your client CA → handshake fails.
* Client cert OK but ClickHouse user mapping missing → ClickHouse authentication fails after handshake.
* Client trusts wrong CA bundle for server → certificate verify failed.

<br> 

In case of error, AI can pinpoint which layer is failing (TLS handshake vs ClickHouse auth). Paste the ClickHouse **users.d** snippet you created for svc_livewire and the exact client-side error.