#pragma once
#include <unordered_map>
#include <string>

class ConfigReader {
public:
    ConfigReader(const std::string& filepath);
    std::string getValue(const std::string& section, const std::string& key) const;

private:
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> config_;
    void loadConfig(const std::string& filepath);
};

std::unordered_map<std::string, std::unordered_map<std::string, std::string>> readConfigFile(const std::string& filepath);

