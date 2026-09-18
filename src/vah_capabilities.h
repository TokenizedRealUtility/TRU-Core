#pragma once

#include <string>
#include <vector>

// VAH-01: Verifiable Attribute History typed capability registry.
//
// IMPORTANT: V1 remains AI-only at the write boundary.  This registry makes
// the field policy explicit and reusable before external writer classes are
// enabled in a later VAH phase.
namespace VAHCapabilities {

enum class WriterClass {
    AI,
    HUMAN,
    SENSOR,
    DEVICE,
    SOFTWARE,
    UNKNOWN
};

enum class Capability {
    AI_DESCRIPTIVE,
    AI_CREATIVE,
    SENSOR_MEASUREMENT,
    DEVICE_STATE,
    HUMAN_ASSERTION,
    APPLICATION_LINK,
    UNKNOWN
};

struct FieldPolicy {
    const char* field;
    Capability capability;
    unsigned tokenMask;
    unsigned writerMask;
    bool activeInV1;
};

WriterClass writerClassFromString(const std::string& value);
std::string writerClassToString(WriterClass value);
Capability capabilityFromString(const std::string& value);
std::string capabilityToString(Capability value);

// Returns nullptr for unknown/unregistered fields.
const FieldPolicy* fieldPolicy(const std::string& field);

// True when the field is known to the typed VAH catalog and is meaningful for
// the supplied SFT/NCFT token type.  A known field may still be staged for a
// future VAH phase and therefore not writable yet.
bool isKnownFieldForToken(const std::string& tokenType, const std::string& field);

// V1 compatibility gate.  This is intentionally stricter than the complete
// catalog: only the fields already writable by AI Provenance V1 return true.
bool isEvolutionFieldCurrentlyWritable(
    const std::string& tokenType,
    const std::string& writerType,
    const std::string& field
);

// Future-facing policy query.  It does NOT grant authority; it only answers
// whether a writer class is structurally compatible with a registered field.
// Historical signed authorization is a separate VAH layer.
bool writerClassMayHoldFieldCapability(
    const std::string& tokenType,
    const std::string& writerType,
    const std::string& field
);

// True when at least one registered field in the capability is structurally
// compatible with the supplied token/writer class. This is policy only; it is
// not authorization.
bool writerClassMayHoldCapability(
    const std::string& tokenType,
    const std::string& writerType,
    Capability capability
);

std::vector<std::string> fieldsForCapability(
    const std::string& tokenType,
    Capability capability,
    bool activeOnly
);

} // namespace VAHCapabilities
