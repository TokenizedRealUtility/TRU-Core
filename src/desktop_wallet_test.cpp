#include "desktop_wallet_core.h"

#include <sodium.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void require(bool ok, const char* what) {
    if (!ok) {
        std::cerr << "FAIL: " << what << "\n";
        std::exit(1);
    }
}

static std::string fixedRecovery(std::uint32_t count) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string seedHex;
    seedHex.reserve(128);

    for (unsigned i = 0; i < 64; ++i) {
        const unsigned char b =
            static_cast<unsigned char>(i);
        seedHex.push_back(hex[b >> 4]);
        seedHex.push_back(hex[b & 0x0f]);
    }

    return "TRU-DESKTOP-V1:" +
           seedHex + ":" +
           std::to_string(count);
}

static std::string hexBytes(const std::string& text) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(text.size() * 2);
    for (unsigned char b : text) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

static std::string u32le(std::uint32_t v) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(8);
    for (unsigned i = 0; i < 4; ++i) {
        const unsigned char b =
            static_cast<unsigned char>((v >> (8u * i)) & 0xffu);
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

static std::string u64le(std::uint64_t v) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(16);
    for (unsigned i = 0; i < 8; ++i) {
        const unsigned char b =
            static_cast<unsigned char>((v >> (8u * i)) & 0xffu);
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

static std::string smallVarInt(std::size_t v) {
    require(v < 0xfd, "test vector small varint");
    static constexpr char hex[] = "0123456789abcdef";
    const unsigned char b = static_cast<unsigned char>(v);
    std::string out;
    out.push_back(hex[b >> 4]);
    out.push_back(hex[b & 0x0f]);
    return out;
}

int main() {
    namespace fs = std::filesystem;

    const fs::path root =
        fs::temp_directory_path() /
        "tru-desktop-wallet01-test";

    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root);

    const std::string pass =
        "correct horse battery staple / TRU wallet01";
    const std::string wrong =
        "this is definitely the wrong passphrase";

    const fs::path walletA = root / "wallet-a.enc";
    const fs::path walletB = root / "wallet-b.enc";
    const fs::path walletC = root / "wallet-c.enc";
    const fs::path backup = root / "wallet.backup";

    std::string error;

    DesktopWalletCore wallet;
    require(
        wallet.restoreRecovery(
            fixedRecovery(1), walletA.string(),
            pass, &error),
        "restore deterministic recovery vector");

    require(
        wallet.isUnlocked(),
        "wallet unlocked after recovery restore");

    const std::string address0 =
        wallet.currentAddress();

    require(
        !address0.empty() &&
        address0.front() == 'T',
        "TRU address begins with T");

    require(
        wallet.validateAddress(address0),
        "derived address validates");

    // Deterministic vector: same 64-byte seed/path gives same address.
    DesktopWalletCore same;
    require(
        same.restoreRecovery(
            fixedRecovery(1), walletC.string(),
            pass, &error),
        "restore same deterministic vector");
    require(
        same.currentAddress() == address0,
        "same seed/path produces identical address");

    // Wrong password must fail closed.
    wallet.lock();
    require(
        !wallet.unlock(
            walletA.string(), wrong, &error),
        "wrong password rejected");
    require(
        !wallet.isUnlocked(),
        "wrong password leaves wallet locked");

    require(
        wallet.unlock(
            walletA.string(), pass, &error),
        "correct password unlock");

    // Generate another address and persist counter.
    std::string address1;
    require(
        wallet.createNextAddress(
            walletA.string(), pass,
            address1, &error),
        "generate second address");
    require(
        address1 != address0,
        "second address differs");
    require(
        wallet.addressCount() == 2,
        "address counter advanced");

    // Encrypted backup/restore must preserve exact address set.
    require(
        wallet.backup(
            walletA.string(),
            backup.string(), &error),
        "encrypted backup");

    wallet.lock();

    require(
        wallet.restoreBackup(
            backup.string(),
            walletB.string(),
            pass, &error),
        "encrypted backup restore");

    require(
        wallet.addressCount() == 2,
        "backup restores address counter");
    require(
        wallet.address(0) == address0 &&
        wallet.address(1) == address1,
        "backup restores deterministic addresses");

    // Authenticated encryption must reject a one-byte tamper.
    {
        std::fstream f(
            walletB,
            std::ios::in |
            std::ios::out |
            std::ios::binary);
        require(
            static_cast<bool>(f),
            "open wallet for tamper test");
        f.seekg(-1, std::ios::end);
        char b = 0;
        f.read(&b, 1);
        b ^= 1;
        f.seekp(-1, std::ios::end);
        f.write(&b, 1);
    }

    DesktopWalletCore tamper;
    require(
        !tamper.unlock(
            walletB.string(), pass, &error),
        "authenticated encryption rejects tamper");

    // Local transaction construction/signing. No node is involved.
    DesktopWalletCore signer;
    const fs::path walletD = root / "wallet-d.enc";
    require(
        signer.restoreRecovery(
            fixedRecovery(1),
            walletD.string(), pass, &error),
        "restore signing wallet");

    DesktopWalletUtxo u;
    u.txid = std::string(64, '1');
    u.vout = 0;
    u.amountAtoms = 200000;
    u.keyIndex = 0;
    u.scriptPubKey =
        signer.scriptForAddress(
            signer.currentAddress());

    const auto signedTx =
        signer.buildAndSign(
            {u},
            signer.currentAddress(),
            100000,
            10000);

    require(
        !signedTx.rawHex.empty(),
        "signed raw transaction produced");
    require(
        signedTx.txid.size() == 64,
        "local txid is 32-byte hex");
    require(
        signedTx.feeAtoms == 10000,
        "minimum fee exact");
    require(
        signedTx.changeAtoms == 90000,
        "change exact");

    // Sign a Core-built prepared transaction locally while preserving the
    // exact token-metadata serialization tail covered by SIGHASH_ALL.
    const std::string preparedPrevTxid(64, '2');
    const std::string localScript =
        signer.scriptForAddress(signer.currentAddress());
    const std::string metadata =
        R"({"token":"prepared-signing-test"})";

    std::string preparedHex;
    preparedHex += u32le(1);                 // version
    preparedHex += "01";                     // one input
    preparedHex += preparedPrevTxid;
    preparedHex += u32le(0);                 // vout
    preparedHex += "00";                     // empty scriptSig
    preparedHex += u32le(0xffffffffu);       // sequence
    preparedHex += "01";                     // one output
    preparedHex += u64le(1);                 // 1 atom control output
    preparedHex += smallVarInt(localScript.size() / 2);
    preparedHex += localScript;
    preparedHex += u32le(0);                 // lockTime
    preparedHex += "01";                     // token metadata present
    preparedHex += smallVarInt(metadata.size());
    preparedHex += hexBytes(metadata);

    DesktopWalletUtxo preparedInput;
    preparedInput.txid = preparedPrevTxid;
    preparedInput.vout = 0;
    preparedInput.amountAtoms = 1;
    preparedInput.scriptPubKey = localScript;
    preparedInput.keyIndex = 0;

    const auto preparedSigned =
        signer.signPrepared(
            preparedHex,
            {preparedInput});

    require(
        !preparedSigned.rawHex.empty(),
        "prepared transaction signed locally");
    require(
        preparedSigned.txid.size() == 64,
        "prepared transaction stable txid produced");
    require(
        preparedSigned.rawHex.find(hexBytes(metadata)) !=
            std::string::npos,
        "prepared token metadata preserved exactly");

    DesktopWalletUtxo badPreparedInput = preparedInput;
    badPreparedInput.scriptPubKey =
        std::string("76a914") +
        std::string(40, '0') +
        "88ac";
    bool refusedBadDescriptor = false;
    try {
        (void)signer.signPrepared(
            preparedHex,
            {badPreparedInput});
    } catch (...) {
        refusedBadDescriptor = true;
    }
    require(
        refusedBadDescriptor,
        "prepared input not controlled by local key is refused");

    std::string authPub;
    std::string authSig;
    require(
        signer.signMessageSha256(
            signer.currentAddress(),
            "TRU-TEST-AUTHORIZATION-V1\n",
            authPub,
            authSig,
            &error),
        "domain authorization message signed");
    require(
        authPub.size() == 66 && !authSig.empty(),
        "authorization returns compressed public key and DER signature");

    // Recovery seed bytes must never appear in serialized transaction data.
    const std::string recovery =
        fixedRecovery(1);
    const std::size_t pfx =
        std::string("TRU-DESKTOP-V1:").size();
    const std::string seedHex =
        recovery.substr(pfx, 128);

    require(
        signedTx.rawHex.find(seedHex) ==
            std::string::npos,
        "seed absent from signed transaction");

    std::uint64_t parsed = 0;
    require(
        DesktopWalletCore::parseAmount(
            "1.23456789", parsed, &error) &&
        parsed == 123456789ULL,
        "exact decimal amount parser");

    require(
        !DesktopWalletCore::parseAmount(
            "0.000000001", parsed, &error),
        "more than 8 decimals rejected");

    fs::remove_all(root, ec);

    std::cout
        << "PASS: encrypted wallet; wrong-password/tamper rejection; "
           "canonical TRU HD address derivation; deterministic recovery; "
           "backup/restore; local P2PKH signing; prepared token/TRUScript signing; "
           "authorization signing; exact money parser; seed absent from broadcast payload\n";
    return 0;
}
