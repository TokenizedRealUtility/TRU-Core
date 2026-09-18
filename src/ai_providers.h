#pragma once
#include <memory>
#include "ai_provider_interface.h"

// Factory functions (implemented in ai_providers.cpp)
std::shared_ptr<IAIProvider> makeOobaboogaProvider();
std::shared_ptr<IAIProvider> makeOpenAIProvider();
std::shared_ptr<IAIProvider> makeAnthropicProvider();
std::shared_ptr<IAIProvider> makeNemotronProvider();
std::shared_ptr<IAIProvider> makeOllamaProvider();
std::shared_ptr<IAIProvider> makeGrokProvider();
std::shared_ptr<IAIProvider> makeGeminiProvider();
std::shared_ptr<IAIProvider> makeCustomProvider();

