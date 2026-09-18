#include "blockchain.h"
#include "p2p.h"
#include "blockexplorer.h"
#include "logging.h"
#include <iostream>
#include <filesystem>
#include <stdexcept>
#include <thread> // For std::this_thread::sleep_for
#include <chrono> // For std::chrono::seconds
#include "tru_network_params.h"

int main(int argc, char* argv[]) {
    try {
        // Initialize Logger
        Logger::init("explorer.log");
        Logger::log("[explorer_main] Starting block explorer...");

        // Parse command-line arguments
        if (argc < 2) {
            Logger::log("[explorer_main] ERROR: Usage: blockexplorer <utxoDBPath> [port]");
            std::cerr << "Usage: blockexplorer <utxoDBPath> [port]" << std::endl;
            Logger::shutdown();
            return 1;
        }

        std::string dbPath = argv[1];
        int port = (argc >= 3) ? std::stoi(argv[2]) : 8080;

        // Ensure data directory exists
        if (!std::filesystem::exists(dbPath)) {
            Logger::log("[explorer_main] Creating data directory: " + dbPath);
            std::filesystem::create_directories(dbPath);
        }

        // Initialize P2PNode and Blockchain with circular dependency handling
        Logger::log("[explorer_main] Initializing P2PNode");
        std::unique_ptr<P2PNode> node = std::make_unique<P2PNode>();

        Logger::log("[explorer_main] Initializing Blockchain with P2PNode reference");
        std::unique_ptr<Blockchain> chain = std::make_unique<Blockchain>(dbPath, std::string(tru_network::GENESIS_ADDRESS), *node);

        Logger::log("[explorer_main] Linking Blockchain pointer to P2PNode");
        node->setBlockchain(chain.get()); // Update P2PNode with the Blockchain pointer

        // Load blockchain state
        if (!chain->loadChainState()) {
            Logger::log("[explorer_main] ERROR: Failed to load blockchain state from " + dbPath);
            std::cerr << "Failed to load blockchain state from " << dbPath << std::endl;
            Logger::shutdown();
            return 1;
        }
        Logger::log("[explorer_main] Blockchain state loaded successfully. Best tip height: " + 
                    std::to_string(chain->getBestTipHeight()));

        // Start P2PNode listening
        Logger::log("[explorer_main] Starting P2PNode listening on port " + std::to_string(tru_network::MAINNET_P2P_PORT));
        node->startListening(tru_network::MAINNET_P2P_PORT, chain.get());

        // Initialize and start BlockExplorer
        Logger::log("[explorer_main] Initializing BlockExplorer");
        BlockExplorer explorer(chain.get()); // Pass raw pointer as per original design
        Logger::log("[explorer_main] Starting block explorer server on port: " + std::to_string(port));
        explorer.startServer(port);

        // Keep the application running
        Logger::log("[explorer_main] Block explorer server running. Entering main loop...");
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        Logger::shutdown();
        return 0;
    } catch (const std::exception& e) {
        Logger::log("[explorer_main] ERROR: " + std::string(e.what()));
        std::cerr << "Error: " << e.what() << std::endl;
        Logger::shutdown();
        return 1;
    } catch (...) {
        Logger::log("[explorer_main] FATAL: Unknown error");
        std::cerr << "Fatal: Unknown error" << std::endl;
        Logger::shutdown();
        return 2;
    }
}
