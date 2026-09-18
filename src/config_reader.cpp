#include "config_reader.h"
#include <fstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <string>
#include "utils.h"


ConfigReader::ConfigReader(const std::string& filepath) {
    config_ = readConfigFile(filepath);
}

std::string ConfigReader::getValue(const std::string& section, const std::string& key) const {
    auto sectionIt = config_.find(section);
    if (sectionIt != config_.end()) {
        auto keyIt = sectionIt->second.find(key);
        if (keyIt != sectionIt->second.end()) {
            return keyIt->second;
        }
    }
    return "";
}

std::unordered_map<std::string, std::unordered_map<std::string, std::string>> readConfigFile(const std::string &filepath)
{   
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> cfg;
    std::ifstream in(filepath);
    if(!in.is_open()) {
        throw std::runtime_error("Cannot open config file: " + filepath);
    }
    std::string line;
    std::string currentSection = "default"; // Default section for keys outside any section
    while(std::getline(in, line)) {
        // Trim leading and trailing whitespace
        line = trim(line);
        // Skip empty lines or comments
        if(line.empty() || line[0] == '#') continue;

        if(line[0] == '[') {
            // Handle section header
            size_t end = line.find(']', 1);
            if(end != std::string::npos) {
                currentSection = trim(line.substr(1, end - 1));
            }
        } else {
            auto eqPos = line.find('=');
            if(eqPos != std::string::npos) {
                std::string key = trim(line.substr(0, eqPos));
                std::string value = trim(line.substr(eqPos + 1));
                cfg[currentSection][key] = value;
            }
        }
    }
    return cfg;
}

