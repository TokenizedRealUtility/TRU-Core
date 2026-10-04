#pragma once

// CLI-ADDRESS-SELECT-01: local wallet selection only; no RPC or transactions.
#include <algorithm>
#include <cerrno>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <termios.h>
#include <unistd.h>

namespace tru_cli_address_selection_v1 {

inline std::size_t resolve(const std::string& input,
                           const std::vector<std::string>& addresses) {
    const auto found = std::find(addresses.begin(), addresses.end(), input);
    if (found != addresses.end()) return static_cast<std::size_t>(found - addresses.begin());
    if (input.empty()) throw std::runtime_error("Enter an address number or a full wallet address.");
    std::size_t index = 0;
    for (const unsigned char c : input) {
        if (c < '0' || c > '9' ||
            index > (std::numeric_limits<std::size_t>::max() - (c - '0')) / 10)
            throw std::runtime_error("Invalid selection. Use a listed number or a full wallet address.");
        index = index * 10 + (c - '0');
    }
    if (index >= addresses.size()) throw std::runtime_error("Address number is out of range.");
    return index;
}

class Secret {
public:
    std::string value;
    Secret() = default;
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    ~Secret() noexcept {
        if (!value.empty()) {
            volatile char* bytes = &value[0];
            for (std::size_t i = 0; i < value.size(); ++i) bytes[i] = 0;
        }
    }
};

class HiddenInput {
    termios saved_{};
    bool active_ = false;
    static int set(const termios& settings) noexcept {
        int result;
        do { result = ::tcsetattr(STDIN_FILENO, TCSANOW, &settings); }
        while (result < 0 && errno == EINTR);
        return result;
    }
public:
    HiddenInput() {
        if (!::isatty(STDIN_FILENO) || ::tcgetattr(STDIN_FILENO, &saved_) != 0)
            throw std::runtime_error("Address selection requires an interactive terminal for the passphrase.");
        termios hidden = saved_;
        hidden.c_lflag &= static_cast<tcflag_t>(~(ECHO | ECHONL));
        // Do not suspend the process with terminal echo disabled.
        hidden.c_cc[VSUSP] = _POSIX_VDISABLE;
        if (set(hidden) != 0) throw std::runtime_error("Cannot disable terminal echo.");
        active_ = true;
    }
    HiddenInput(const HiddenInput&) = delete;
    HiddenInput& operator=(const HiddenInput&) = delete;
    void restore() {
        if (active_ && set(saved_) != 0)
            throw std::runtime_error("Cannot restore terminal settings; selection cancelled.");
        active_ = false;
    }
    ~HiddenInput() noexcept { if (active_) (void)set(saved_); }
};

// Mode is the wallet's existing enum; the caller passes its named constants.
// Reader must preserve the Core's signal-aware input and shutdown exceptions.
template<class WalletLike, class Mode, class Reader>
bool select(WalletLike& wallet, const std::string& address,
            Mode legacy, Mode unlocked, Reader readLine, std::ostream& output) {
    const auto owned = wallet.getAllAddresses();
    if (std::find(owned.begin(), owned.end(), address) == owned.end())
        throw std::runtime_error("Selected address is not in this wallet.");
    if (wallet.getCurrentAddress() == address) return true;
    const auto mode = wallet.getWalletSecurityMode();
    if (mode == legacy) {
        wallet.setCurrentAddress(address);
        return true;
    }
    if (mode != unlocked)
        throw std::runtime_error("Wallet is locked. Unlock the Core wallet before selecting an address.");
    Secret secret;
    {
        HiddenInput terminal;
        output << "Wallet passphrase (hidden; Enter cancels): " << std::flush;
        const bool read = readLine(secret.value);
        terminal.restore();
        output << '\n';
        if (!read || secret.value.empty()) return false;
    }
    std::string error;
    if (!wallet.setCurrentAddressEncrypted(address, secret.value, &error))
        throw std::runtime_error(error.empty() ? "Authenticated address selection failed." : error);
    return true;
}
} // namespace tru_cli_address_selection_v1
