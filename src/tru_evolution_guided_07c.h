#pragma once
// TRU-AI-EVOLVE-07C — manual guided prompts only; NEVER an external fact oracle.
// This header is UI-only and cannot write token state, bypass the original
// issuer signature, change balances/supply, or submit/confirm an on-chain anchor.
#include "tru_evolution_scenarios_07.h"
#include <array>
#include <cctype>
#include <stdexcept>
#include <string>

namespace tru_evolve_guided07c {
struct Guide {
    const char* id;
    const char* milestone;
    const char* change;
    const char* evidence;
    const char* appearance;
};

inline constexpr std::array<Guide, 7> guides{{
    {"game", "What victory, quest or chapter has the issuer recorded?",
     "What armor, abilities or story traits changed?",
     "Game session or achievement reference (optional, not verified):",
     "Requested new look or story artwork (optional):"},
    {"equipment", "What service or operating-hours milestone occurred?",
     "Which component, condition or maintenance record changed?",
     "Public service log or work-order reference (optional, not verified):",
     "Requested equipment photo or visual style (optional):"},
    {"property", "What construction, inspection or renovation stage was reached?",
     "What was the previous stage and what changed?",
     "Public permit, inspection or project reference (optional, not verified):",
     "Updated property photo or architectural style (optional):"},
    {"ticket", "What event or attendance milestone is being recorded?",
     "How should this ticket's commemorative description change?",
     "Issuer scan or event reference (optional, not verified):",
     "Keepsake artwork or visual treatment (optional):"},
    {"membership", "What membership milestone does the issuer report?",
     "What descriptive stage or badge changed?",
     "Public issuer eligibility reference (optional, not verified):",
     "New badge or membership artwork (optional):"},
    {"product", "What manufacturing, inspection or delivery milestone occurred?",
     "What product status, component or descriptive trait changed?",
     "Public batch, shipping or inspection reference (optional, not verified):",
     "Updated product image or packaging art (optional):"},
    {"kraken", "What collection-wide milestone did the issuer approve?",
     "How should the shared Energy Cells lore or stage evolve?",
     "Public project announcement reference (optional, not verified):",
     "Requested shared SFT collection artwork (optional):"}
}};

inline constexpr Guide customGuide{
    "custom", "What actual milestone are you documenting?",
    "What descriptive traits, narrative or status changed?",
    "Public supporting reference (optional, not verified):",
    "Requested artwork or style (optional):"
};

inline const Guide& forScenario(const tru_evolve_scenarios07::Scenario& scenario) {
    for (const auto& guide : guides)
        if (std::string(scenario.id) == guide.id) return guide;
    throw std::invalid_argument("Unsupported scenario identifier");
}

struct Answers {
    std::string milestone;
    std::string change;
    std::string evidence;
    std::string appearance;
};

inline std::string field(std::string value, size_t maxBytes, bool required,
                         const char* name) {
    // Normalize only line breaks and tabs from Qt multi-line fields.
    for (char& c : value) if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    const size_t first = value.find_first_not_of(' ');
    if (first == std::string::npos) value.clear();
    else {
        const size_t last = value.find_last_not_of(' ');
        value = value.substr(first, last - first + 1U);
    }
    if ((required && value.empty()) || value.size() > maxBytes)
        throw std::invalid_argument(std::string(name) + " must be " +
            (required ? "1.." : "0..") + std::to_string(maxBytes) + " UTF-8 bytes");
    for (unsigned char c : value)
        if (c < 32U || c == 127U)
            throw std::invalid_argument(std::string(name) + " contains control characters");
    return value;
}

inline std::string compose(const std::string& scenarioId,
                           const std::string& scope, const Answers& supplied) {
    if (scenarioId.empty() || scenarioId.size() > 64U)
        throw std::invalid_argument("Invalid scenario identifier");
    const auto milestone = field(supplied.milestone, 160U, true, "Milestone");
    const auto change = field(supplied.change, 100U, false, "Changed traits");
    const auto evidence = field(supplied.evidence, 80U, false, "Evidence reference");
    const auto appearance = field(supplied.appearance, 100U, false, "Art direction");
    std::string trigger = "MANUAL ISSUER-REPORTED GUIDED EVOLUTION [" + scenarioId + "]: " +
        scope + " Milestone: " + milestone + ".";
    if (!change.empty()) trigger += " Changes: " + change + ".";
    if (!evidence.empty()) trigger += " Unverified public reference: " + evidence + ".";
    if (!appearance.empty()) trigger += " Requested art/style (not generated): " + appearance + ".";
    trigger += " The issuer reports this, external facts are unverified. "
               "Do not invent events or grant rights; only propose engine-permitted descriptive fields.";
    if (trigger.size() > 1024U)
        throw std::invalid_argument("Guided trigger exceeds 1024 UTF-8 bytes; shorten responses");
    return trigger;
}

inline std::string composeScenario(const tru_evolve_scenarios07::Scenario& scenario,
                                   const std::string& tokenType,
                                   const Answers& supplied) {
    if (!tru_evolve_scenarios07::availableFor(scenario, tokenType))
        throw std::invalid_argument("Template unavailable for this token type");
    (void)forScenario(scenario);
    return compose(scenario.id, scenario.prompt, supplied);
}

inline std::string composeCustom(const std::string& title,
                                 const std::string& tokenType,
                                 const Answers& supplied) {
    if (tokenType != "SFT" && tokenType != "NCFT")
        throw std::invalid_argument("Guided evolution supports only SFT/NCFT");
    const auto safeTitle = field(title, 64U, true, "Custom template name");
    return compose("custom", "Issuer-defined scenario '" + safeTitle +
        "'. Describe only permitted token-level metadata changes.", supplied);
}
} // namespace tru_evolve_guided07c
