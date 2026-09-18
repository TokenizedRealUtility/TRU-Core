#include "vah_capabilities.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}
}

int main() {
    using namespace VAHCapabilities;

    require(writerClassFromString("AI") == WriterClass::AI,
            "writer class parsing must be case-insensitive");
    require(writerClassFromString("root") == WriterClass::UNKNOWN,
            "unknown writer class must fail closed");

    // Exact AI Provenance V1 compatibility matrix.
    require(isEvolutionFieldCurrentlyWritable("SFT", "ai", "description_ai"),
            "SFT description_ai must remain active");
    require(isEvolutionFieldCurrentlyWritable("SFT", "ai", "ai_version"),
            "SFT ai_version must remain active");
    require(isEvolutionFieldCurrentlyWritable("NCFT", "ai", "style_descriptor"),
            "NCFT style_descriptor must remain active");
    require(isEvolutionFieldCurrentlyWritable("NCFT", "ai", "update_interval"),
            "NCFT update_interval must remain active");

    // Registered future capabilities are known but not enabled by VAH-01ABC.
    require(isKnownFieldForToken("SFT", "sentiment_score"),
            "SFT sentiment_score must be registered");
    require(writerClassMayHoldFieldCapability("SFT", "sensor", "sentiment_score"),
            "sensor must structurally match sentiment_score");
    require(!isEvolutionFieldCurrentlyWritable("SFT", "sensor", "sentiment_score"),
            "sensor writes must remain disabled in V1");

    require(isKnownFieldForToken("NCFT", "neural_art_evolution"),
            "NCFT neural_art_evolution must be registered");
    require(writerClassMayHoldFieldCapability("NCFT", "ai", "neural_art_evolution"),
            "AI must structurally match neural_art_evolution");
    require(!isEvolutionFieldCurrentlyWritable("NCFT", "ai", "neural_art_evolution"),
            "new AI fields must not silently expand V1 allowlist");

    require(writerClassMayHoldFieldCapability("NCFT", "software", "atomic_swap_ncft_chain"),
            "software must structurally match NCFT swap link");
    require(!writerClassMayHoldFieldCapability("SFT", "software", "atomic_swap_ncft_chain"),
            "NCFT swap field must not cross token types");

    // Engine/protocol-controlled names are intentionally absent.
    require(fieldPolicy("evolution_epoch") == nullptr,
            "evolution_epoch must remain engine-controlled");
    require(fieldPolicy("creator_signature") == nullptr,
            "creator_signature must not be decorative mutable metadata");
    require(fieldPolicy("self_evolution") == nullptr,
            "self_evolution must be policy, not a metadata permission bit");
    require(fieldPolicy("owner") == nullptr,
            "ownership must remain outside VAH mutable fields");
    require(fieldPolicy("supply") == nullptr,
            "supply must remain outside VAH mutable fields");

    std::cout << "TRU_VAH_01_TYPED_CAPABILITY_MATRIX=PASS\n";
    return 0;
}
