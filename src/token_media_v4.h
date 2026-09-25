#pragma once

// Application-level descriptive evolution. No spend or consensus fields.
// V1/V2 field policy and request preimages MUST remain unchanged.
#include "vah_capabilities.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>

namespace tru_media_v4 {
using nlohmann::json;
inline bool digest(const std::string& s) {
    return s.size() == 64 && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
inline bool uri(const std::string& s) {
    if (s.empty() || s.size() > 1024 || s.find_first_of("\\\"<>@") != std::string::npos)
        return false;
    if (std::any_of(s.begin(), s.end(), [](unsigned char c){return c <= 32 || c >= 127;}))
        return false;
    // URI is a reference, not evidence of availability or matching bytes.
    if (s.rfind("https://", 0) == 0) return s.size() > 8 && s[8] != '/' && s[8] != '.';
    if (s.rfind("ipfs://", 0) == 0) return s.size() > 7 && s[7] != '/';
    return false;
}
inline void require(bool b, const char* why) { if (!b) throw std::invalid_argument(why); }
inline bool aiField(const std::string& type, const std::string& key) {
    static const std::set<std::string> common = {
        "analysis_summary", "condition_summary", "narrative", "traits"
    };
    return (type == "SFT" || type == "NCFT") &&
        (VAHCapabilities::isEvolutionFieldCurrentlyWritable(type, "ai", key) || common.count(key));
}
inline bool inputField(const std::string& key) {
    static const std::set<std::string> fields = {
        "image", "artwork_sha256", "change_note", "source_reference", "source_sha256",
        "generation_model", "generation_prompt_sha256"
    };
    return fields.count(key) != 0;
}
inline void validateInputs(const json& in) {
    require(in.is_object() && in.size() <= 7 && in.dump().size() <= 12288,
            "Media inputs must be a bounded JSON object");
    for (auto it = in.begin(); it != in.end(); ++it) {
        require(inputField(it.key()) && it.value().is_string(), "Unknown media input or non-string value");
        const auto s = it.value().get<std::string>();
        require(!s.empty() && s.size() <= 2048, "Empty or oversized media input");
        require(std::none_of(s.begin(), s.end(), [](unsigned char c){return c < 32 || c == 127;}),
                "Control characters forbidden in media input");
        if (it.key() == "image" || it.key() == "source_reference")
            require(uri(s), "Media references must use HTTPS or ipfs://");
        if (it.key().find("sha256") != std::string::npos)
            require(digest(s), "Digest must be 64 lowercase hexadecimal characters");
    }
    require(in.contains("image") == in.contains("artwork_sha256"), "Image and artwork_sha256 are required together");
    require(!in.contains("image") || in.contains("change_note"), "Image upgrade requires change_note");
    require(!in.contains("source_sha256") || in.contains("source_reference"), "Source digest requires source reference");
    require((!in.contains("generation_model") && !in.contains("generation_prompt_sha256")) || in.contains("image"),
            "Generation claims require an image revision");
}
inline json ownedUpdates(const json& inputs, const json& parent, uint64_t epoch) {
    validateInputs(inputs);
    json out = inputs;
    if (inputs.contains("image")) {
        require(inputs.at("image") != parent.value("image", json()),
                "Use a new version-specific image URI, not the previous URI");
        require(inputs.at("artwork_sha256") != parent.value("artwork_sha256", json()),
                "Artwork bytes are unchanged");
        out["artwork_version"] = std::to_string(epoch);
        const std::string old = parent.value("artwork_sha256", "");
        out["previous_artwork_sha256"] = digest(old) ? old : "unrecorded";
        // Do not carry a previous image's generation claim onto a new image.
        if (!inputs.contains("generation_model")) out["generation_model"] = "unreported";
        if (!inputs.contains("generation_prompt_sha256")) out["generation_prompt_sha256"] = "unrecorded";
    }
    return out;
}
inline json assemble(const std::string& type, const json& parent, const json& updates,
                     const json& inputs, uint64_t epoch, uint64_t timestamp, const std::string& provider) {
    require((type == "SFT" || type == "NCFT") && parent.is_object() && updates.is_object(), "Invalid V4 token/metadata");
    require(!updates.empty() && updates.size() <= 24 && updates.dump().size() <= 49152, "Invalid V4 update size");
    const json owned = ownedUpdates(inputs, parent, epoch);
    json result = parent;
    bool changed = false;
    for (auto it = updates.begin(); it != updates.end(); ++it) {
        require(it.value().is_string() && it.value().get_ref<const std::string&>().size() <= 2048, "Invalid V4 field value");
        if (owned.contains(it.key())) require(owned.at(it.key()) == it.value(), "Owner input changed by provider");
        else require(aiField(type, it.key()), "Forbidden V4 field");
        changed |= !parent.contains(it.key()) || parent.at(it.key()) != it.value();
        result[it.key()] = it.value();
    }
    for (auto it = owned.begin(); it != owned.end(); ++it)
        require(updates.contains(it.key()) && updates.at(it.key()) == it.value(), "Missing owner input");
    require(changed, "No effective metadata change");
    result["ai_engine"] = provider;
    result["evolution_epoch"] = std::to_string(epoch);
    result["last_evolution"] = "unix:" + std::to_string(timestamp) + ";epoch:" + std::to_string(epoch);
    require(result.dump().size() <= 1024U * 1024U, "V4 metadata too large");
    return result;
}
} // namespace tru_media_v4
