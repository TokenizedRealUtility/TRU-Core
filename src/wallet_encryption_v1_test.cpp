#include "wallet_encryption_v1.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace enc = tru_wallet_encryption_v1;

static void require(bool ok, const char* what)
{
    if (!ok) {
        std::cerr << "FAIL: " << what << "\n";
        std::exit(1);
    }
}

int main()
{
    const std::string pass = "correct horse battery staple / TRU SEC-14B.2";
    const std::string wrong = "wrong password";

    const std::vector<std::uint8_t> plain = {
        0x00, 0x01, 0x02, 0x7f, 0x80, 0xff,
        'P','E','M','\n','R','A','W','\0','K','E','Y'
    };

    std::vector<std::uint8_t> env1;
    std::vector<std::uint8_t> env2;
    std::vector<std::uint8_t> out;
    std::string err;

    require(enc::encrypt(plain, pass, env1, &err),
            "encrypt round-trip vector");
    require(enc::isEnvelopeV1(env1),
            "recognize V1 envelope");
    require(enc::decrypt(env1, pass, out, &err),
            "decrypt round-trip vector");
    require(out == plain,
            "binary plaintext preserved exactly");

    require(enc::encrypt(plain, pass, env2, &err),
            "second encryption");
    require(env1 != env2,
            "salt/nonce randomize identical plaintext+passphrase");

    out.clear();
    require(!enc::decrypt(env1, wrong, out, &err),
            "wrong password rejected");
    require(out.empty(),
            "wrong-password path returns no plaintext");

    auto tamperedCipher = env1;
    tamperedCipher.back() ^= 0x01;
    out.clear();
    require(!enc::decrypt(tamperedCipher, pass, out, &err),
            "ciphertext/tag tamper rejected");
    require(out.empty(),
            "tamper path returns no plaintext");

    auto tamperedHeader = env1;
    tamperedHeader[9] ^= 0x01; // KDF id byte
    out.clear();
    require(!enc::decrypt(tamperedHeader, pass, out, &err),
            "header tamper rejected");

    auto tamperedCanonicalParams = env1;
    tamperedCanonicalParams[12] ^= 0x01; // opslimit metadata
    out.clear();
    require(!enc::decrypt(tamperedCanonicalParams, pass, out, &err),
            "noncanonical KDF parameters rejected before allocation/KDF");

    auto truncated = env1;
    truncated.resize(enc::headerSize());
    out.clear();
    require(!enc::decrypt(truncated, pass, out, &err),
            "truncated ciphertext rejected");

    std::vector<std::uint8_t> emptyEnv;
    require(!enc::encrypt(plain, "", emptyEnv, &err),
            "empty passphrase rejected");
    require(emptyEnv.empty(),
            "empty-passphrase path creates no envelope");

    const std::vector<std::uint8_t> emptyPlain;
    std::vector<std::uint8_t> emptyRoundTrip;
    require(enc::encrypt(emptyPlain, pass, emptyEnv, &err),
            "empty plaintext encryption supported");
    require(enc::decrypt(emptyEnv, pass, emptyRoundTrip, &err),
            "empty plaintext decrypt supported");
    require(emptyRoundTrip.empty(),
            "empty plaintext preserved");

    std::cout << "SEC_14B2_ENVELOPE_ROUNDTRIP=PASS\n";
    std::cout << "SEC_14B2_BINARY_PRESERVATION=PASS\n";
    std::cout << "SEC_14B2_RANDOM_SALT_NONCE=PASS\n";
    std::cout << "SEC_14B2_WRONG_PASSWORD_REJECTION=PASS\n";
    std::cout << "SEC_14B2_CIPHERTEXT_TAMPER_REJECTION=PASS\n";
    std::cout << "SEC_14B2_HEADER_TAMPER_REJECTION=PASS\n";
    std::cout << "SEC_14B2_KDF_PARAMETER_BOUNDS=PASS\n";
    std::cout << "SEC_14B2_TRUNCATION_REJECTION=PASS\n";
    std::cout << "SEC_14B2_EMPTY_PASSPHRASE_REJECTION=PASS\n";
    std::cout << "TRU_SEC_14B2_WALLET_ENCRYPTED_ENVELOPE_FOUNDATION=PASS\n";
    return 0;
}
