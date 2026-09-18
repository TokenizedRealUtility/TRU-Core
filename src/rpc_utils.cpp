#include "rpc_utils.h"
#include <httplib.h>
#include "logging.h"
#include <thread>
#include <chrono>

// RPC Call with Retries
nlohmann::json rpcCall(const std::string& method, const nlohmann::json& params, const std::string& nodeIP, int nodePort, int retries, int delay) {
    for (int attempt = 0; attempt < retries; ++attempt) {
        try {
            httplib::Client cli(nodeIP, nodePort);
            cli.set_connection_timeout(5, 0);
            cli.set_read_timeout(10, 0);
            nlohmann::json req{{"method", method}, {"params", params}};
            Logger::log("Making RPC call: " + method);
            auto resp = tru_rpc::post(cli, req.dump(), nodePort);
            if (!resp || resp->status != 200) {
                throw std::runtime_error("RPC call failed: " + method + " (Status: " + (resp ? std::to_string(resp->status) : "No response") + ")");
            }
            Logger::log("RPC call " + method + " succeeded");
            return nlohmann::json::parse(resp->body);
        } catch (const std::exception& e) {
            if (attempt < retries - 1) {
                Logger::log("Retrying RPC call: " + method + " after " + std::to_string(delay) + "s");
                std::this_thread::sleep_for(std::chrono::seconds(delay));
            } else {
                throw std::runtime_error("RPC call " + method + " failed after " + std::to_string(retries) + " attempts: " + e.what());
            }
        }
    }
    throw std::runtime_error("RPC call failed unexpectedly");
}
