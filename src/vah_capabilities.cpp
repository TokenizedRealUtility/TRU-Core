#include "vah_capabilities.h"

#include <algorithm>
#include <array>
#include <cctype>

namespace VAHCapabilities {
namespace {

constexpr unsigned TOKEN_SFT  = 1U << 0U;
constexpr unsigned TOKEN_NCFT = 1U << 1U;

constexpr unsigned WRITER_AI       = 1U << 0U;
constexpr unsigned WRITER_HUMAN    = 1U << 1U;
constexpr unsigned WRITER_SENSOR   = 1U << 2U;
constexpr unsigned WRITER_DEVICE   = 1U << 3U;
constexpr unsigned WRITER_SOFTWARE = 1U << 4U;

constexpr unsigned BOTH_TOKENS = TOKEN_SFT | TOKEN_NCFT;

// VAH-01 typed field catalog.  activeInV1 is deliberately true only for the
// exact AI Provenance V1 allowlist.  Other entries are registered semantics,
// not newly-enabled mutation authority.
constexpr std::array<FieldPolicy, 31> POLICIES{{
    {"description_ai",          Capability::AI_DESCRIPTIVE,    BOTH_TOKENS, WRITER_AI, true},
    {"ai_version",              Capability::AI_DESCRIPTIVE,    TOKEN_SFT,   WRITER_AI, true},
    {"learning_mode",           Capability::AI_DESCRIPTIVE,    TOKEN_SFT,   WRITER_AI, true},
    {"growth_algorithm",        Capability::AI_DESCRIPTIVE,    TOKEN_SFT,   WRITER_AI, true},
    {"adaptation_rate",         Capability::AI_DESCRIPTIVE,    TOKEN_SFT,   WRITER_AI, true},
    {"behavior_model",          Capability::AI_DESCRIPTIVE,    TOKEN_SFT,   WRITER_AI, false},

    {"style_descriptor",        Capability::AI_CREATIVE,       TOKEN_NCFT,  WRITER_AI, true},
    {"dynamic_morph",           Capability::AI_CREATIVE,       TOKEN_NCFT,  WRITER_AI, true},
    {"update_interval",         Capability::AI_CREATIVE,       TOKEN_NCFT,  WRITER_AI, true},
    {"neural_art_evolution",    Capability::AI_CREATIVE,       TOKEN_NCFT,  WRITER_AI, false},
    {"dynamic_narrative_link",  Capability::AI_CREATIVE,       TOKEN_NCFT,  WRITER_AI, false},
    {"generative_seed",         Capability::AI_CREATIVE,       TOKEN_NCFT,  WRITER_AI | WRITER_SOFTWARE, false},

    {"sentiment_score",         Capability::SENSOR_MEASUREMENT,TOKEN_SFT,   WRITER_SENSOR | WRITER_SOFTWARE, false},
    {"emotional_resonance",     Capability::SENSOR_MEASUREMENT,TOKEN_SFT,   WRITER_SENSOR | WRITER_SOFTWARE, false},
    {"bio_sensor_trigger",      Capability::SENSOR_MEASUREMENT,TOKEN_SFT,   WRITER_SENSOR | WRITER_DEVICE, false},
    {"emotion_response",        Capability::SENSOR_MEASUREMENT,TOKEN_NCFT,  WRITER_SENSOR | WRITER_SOFTWARE, false},
    {"synaptic_pattern_id",     Capability::SENSOR_MEASUREMENT,TOKEN_NCFT,  WRITER_SENSOR | WRITER_DEVICE, false},
    {"biometric_reference",     Capability::SENSOR_MEASUREMENT,BOTH_TOKENS, WRITER_SENSOR | WRITER_DEVICE, false},

    {"operating_state",         Capability::DEVICE_STATE,      BOTH_TOKENS, WRITER_DEVICE | WRITER_SOFTWARE, false},
    {"context_signal",          Capability::DEVICE_STATE,      BOTH_TOKENS, WRITER_DEVICE | WRITER_SOFTWARE, false},
    {"environmental_signal",    Capability::DEVICE_STATE,      BOTH_TOKENS, WRITER_SENSOR | WRITER_DEVICE, false},

    {"privacy_level",           Capability::HUMAN_ASSERTION,   TOKEN_SFT,   WRITER_HUMAN, false},
    {"context_aware_rule",      Capability::HUMAN_ASSERTION,   TOKEN_SFT,   WRITER_HUMAN | WRITER_SOFTWARE, false},
    {"certification_reference", Capability::HUMAN_ASSERTION,   BOTH_TOKENS, WRITER_HUMAN, false},
    {"creator_attribution",     Capability::HUMAN_ASSERTION,   TOKEN_NCFT,  WRITER_HUMAN, false},

    {"defi_insurance_pool",     Capability::APPLICATION_LINK,  TOKEN_SFT,   WRITER_SOFTWARE, false},
    {"atomic_swap_sft_bundle",  Capability::APPLICATION_LINK,  TOKEN_SFT,   WRITER_SOFTWARE, false},
    {"defi_art_loan_value",     Capability::APPLICATION_LINK,  TOKEN_NCFT,  WRITER_SOFTWARE, false},
    {"atomic_swap_ncft_chain",  Capability::APPLICATION_LINK,  TOKEN_NCFT,  WRITER_SOFTWARE, false},
    {"virtual_gallery_space",   Capability::APPLICATION_LINK,  TOKEN_NCFT,  WRITER_HUMAN | WRITER_SOFTWARE, false},
    {"cross_platform_avatar",   Capability::APPLICATION_LINK,  TOKEN_NCFT,  WRITER_HUMAN | WRITER_SOFTWARE, false}
}};

std::string lowerAscii(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
    );
    return value;
}

unsigned tokenMaskFor(const std::string& tokenType) {
    if (tokenType == "SFT") return TOKEN_SFT;
    if (tokenType == "NCFT") return TOKEN_NCFT;
    return 0U;
}

unsigned writerMaskFor(WriterClass writerClass) {
    switch (writerClass) {
        case WriterClass::AI:       return WRITER_AI;
        case WriterClass::HUMAN:    return WRITER_HUMAN;
        case WriterClass::SENSOR:   return WRITER_SENSOR;
        case WriterClass::DEVICE:   return WRITER_DEVICE;
        case WriterClass::SOFTWARE: return WRITER_SOFTWARE;
        case WriterClass::UNKNOWN:  return 0U;
    }
    return 0U;
}

} // namespace

WriterClass writerClassFromString(const std::string& value) {
    const std::string v = lowerAscii(value);
    if (v == "ai") return WriterClass::AI;
    if (v == "human") return WriterClass::HUMAN;
    if (v == "sensor") return WriterClass::SENSOR;
    if (v == "device") return WriterClass::DEVICE;
    if (v == "software") return WriterClass::SOFTWARE;
    return WriterClass::UNKNOWN;
}

std::string writerClassToString(WriterClass value) {
    switch (value) {
        case WriterClass::AI:       return "ai";
        case WriterClass::HUMAN:    return "human";
        case WriterClass::SENSOR:   return "sensor";
        case WriterClass::DEVICE:   return "device";
        case WriterClass::SOFTWARE: return "software";
        case WriterClass::UNKNOWN:  return "unknown";
    }
    return "unknown";
}

Capability capabilityFromString(const std::string& value) {
    const std::string v = lowerAscii(value);
    if (v == "ai_descriptive") return Capability::AI_DESCRIPTIVE;
    if (v == "ai_creative") return Capability::AI_CREATIVE;
    if (v == "sensor_measurement") return Capability::SENSOR_MEASUREMENT;
    if (v == "device_state") return Capability::DEVICE_STATE;
    if (v == "human_assertion") return Capability::HUMAN_ASSERTION;
    if (v == "application_link") return Capability::APPLICATION_LINK;
    return Capability::UNKNOWN;
}

std::string capabilityToString(Capability value) {
    switch (value) {
        case Capability::AI_DESCRIPTIVE:     return "AI_DESCRIPTIVE";
        case Capability::AI_CREATIVE:        return "AI_CREATIVE";
        case Capability::SENSOR_MEASUREMENT: return "SENSOR_MEASUREMENT";
        case Capability::DEVICE_STATE:       return "DEVICE_STATE";
        case Capability::HUMAN_ASSERTION:    return "HUMAN_ASSERTION";
        case Capability::APPLICATION_LINK:   return "APPLICATION_LINK";
        case Capability::UNKNOWN:            return "UNKNOWN";
    }
    return "UNKNOWN";
}

const FieldPolicy* fieldPolicy(const std::string& field) {
    for (const auto& policy : POLICIES) {
        if (field == policy.field) return &policy;
    }
    return nullptr;
}

bool isKnownFieldForToken(const std::string& tokenType, const std::string& field) {
    const FieldPolicy* policy = fieldPolicy(field);
    const unsigned tokenMask = tokenMaskFor(tokenType);
    return policy != nullptr && tokenMask != 0U &&
           (policy->tokenMask & tokenMask) != 0U;
}

bool isEvolutionFieldCurrentlyWritable(
    const std::string& tokenType,
    const std::string& writerType,
    const std::string& field)
{
    const FieldPolicy* policy = fieldPolicy(field);
    if (policy == nullptr || !policy->activeInV1) return false;

    const unsigned tokenMask = tokenMaskFor(tokenType);
    const unsigned writerMask = writerMaskFor(writerClassFromString(writerType));
    return tokenMask != 0U && writerMask != 0U &&
           (policy->tokenMask & tokenMask) != 0U &&
           (policy->writerMask & writerMask) != 0U;
}

bool writerClassMayHoldFieldCapability(
    const std::string& tokenType,
    const std::string& writerType,
    const std::string& field)
{
    const FieldPolicy* policy = fieldPolicy(field);
    if (policy == nullptr) return false;

    const unsigned tokenMask = tokenMaskFor(tokenType);
    const unsigned writerMask = writerMaskFor(writerClassFromString(writerType));
    return tokenMask != 0U && writerMask != 0U &&
           (policy->tokenMask & tokenMask) != 0U &&
           (policy->writerMask & writerMask) != 0U;
}

bool writerClassMayHoldCapability(
    const std::string& tokenType,
    const std::string& writerType,
    Capability capability)
{
    if (capability == Capability::UNKNOWN) return false;
    const auto fields = fieldsForCapability(tokenType, capability, false);
    for (const auto& field : fields) {
        if (writerClassMayHoldFieldCapability(tokenType, writerType, field)) return true;
    }
    return false;
}

std::vector<std::string> fieldsForCapability(
    const std::string& tokenType,
    Capability capability,
    bool activeOnly)
{
    std::vector<std::string> result;
    const unsigned tokenMask = tokenMaskFor(tokenType);
    if (tokenMask == 0U || capability == Capability::UNKNOWN) return result;

    for (const auto& policy : POLICIES) {
        if (policy.capability != capability) continue;
        if ((policy.tokenMask & tokenMask) == 0U) continue;
        if (activeOnly && !policy.activeInV1) continue;
        result.emplace_back(policy.field);
    }
    return result;
}

} // namespace VAHCapabilities
