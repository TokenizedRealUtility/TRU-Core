#pragma once
// TRU-AI-EVOLVE-07: manual, issuer-described use-case prompts ONLY.
// This header does not add a new writable metadata field, an event oracle,
// consensus logic, NFT evolution or authority bypass.
#include <array>
#include <stdexcept>
#include <string>

namespace tru_evolve_scenarios07 {
struct Scenario {
    const char* id;
    const char* title;
    const char* prompt;
    const char* example;
    bool supportsSft;
    bool supportsNcft;
};

inline constexpr std::array<Scenario, 7> scenarios{{
    {"game", "Game character",
     "Describe the character's issuer-reported victory, armor or story progression. "
     "Propose only the descriptive evolution fields permitted for this token type; "
     "do not assert external game results were independently verified.",
     "Quest cleared; armor upgraded to Obsidian; new chapter artwork prepared", true, true},
    {"equipment", "Equipment digital twin",
     "Describe an issuer-reported service milestone, hours, repair or component replacement. "
     "Keep technical claims attributed to the issuer; sensor readings require separately "
     "authenticated evidence before being described as verified.",
     "Excavator 250-hour service; hydraulic filter replaced; service log reference", true, true},
    {"property", "Property and construction",
     "Describe an issuer-reported construction, inspection or renovation stage and "
     "the next visual/story chapter. Do not imply blockchain metadata transfers "
     "real-estate title or authenticates an inspection.",
     "Foundation poured; inspection reference supplied by property issuer", true, true},
    {"ticket", "Event ticket to keepsake",
     "Describe an issuer-reported event milestone and commemorate attendance only "
     "when supported by the issuer's own evidence. No automatic attendance oracle is enabled.",
     "Event completed; issuer confirms ticket was scanned at venue", true, true},
    {"membership", "Membership progression",
     "Describe an issuer-reported Bronze, Silver or Gold milestone. "
     "Do not alter balances, supply or enforce access-control rights through description alone.",
     "Member completed Silver eligibility milestone under issuer rules", true, true},
    {"product", "Product journey",
     "Describe an issuer-reported manufacture, inspection, shipment, delivery "
     "or authentication milestone. Supply-chain claims are not independently "
     "verified merely by an on-chain anchor.",
     "Quality inspection completed; shipment departed; evidence reference available", true, true},
    {"kraken", "Kraken Energy Cells collection (SFT)",
     "Describe an issuer-approved collection-wide Kraken Energy Cells story/artwork "
     "milestone. Evolution updates the shared SFT token metadata; it does not "
     "individually modify each holder's balance or prove an external milestone.",
     "Project milestone reached; new Energy Cells collection artwork approved", true, false}
}};

inline bool availableFor(const Scenario& scenario, const std::string& type) {
    return (type == "SFT" && scenario.supportsSft) ||
           (type == "NCFT" && scenario.supportsNcft);
}

inline bool printableNote(const std::string& note) {
    if (note.empty() || note.size() > 640) return false;
    for (unsigned char c : note) {
        if (c < 32 || c == 127) return false;
    }
    return true;
}

inline std::string composeTrigger(const Scenario& scenario,
                                  const std::string& tokenType,
                                  const std::string& issuerNote) {
    if (!availableFor(scenario, tokenType))
        throw std::invalid_argument("Scenario is not enabled for this token type");
    if (!printableNote(issuerNote))
        throw std::invalid_argument("Issuer note must be 1..640 printable bytes");
    const std::string result =
        std::string("MANUAL ISSUER-REPORTED EVOLUTION [") + scenario.id + "]: " +
        scenario.prompt + " Issuer event/note: " + issuerNote +
        " Treat the note as a claim, not authenticated external evidence.";
    if (result.size() > 1024)
        throw std::invalid_argument("Scenario trigger exceeds 1024 bytes");
    return result;
}
} // namespace tru_evolve_scenarios07
