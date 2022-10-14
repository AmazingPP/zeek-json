#include "Plugin.h"

#include "Converter.h"
#include "config.h"

namespace zeek::plugin::Zeek_JSON
	{
Plugin plugin;
	}

using namespace zeek::plugin::Zeek_JSON;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Zeek::JSON";
	config.description = "JSON parser";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}

void Plugin::InitPreScript()
	{
	json::converters[TYPE_BOOL] = std::make_unique<json::BoolConverter>();
	json::converters[TYPE_INT] = std::make_unique<json::IntConverter>();
	json::converters[TYPE_COUNT] = std::make_unique<json::CountConverter>();
	json::converters[TYPE_DOUBLE] = std::make_unique<json::DoubleConverter>();
	json::converters[TYPE_STRING] = std::make_unique<json::StringConverter>();
	json::converters[TYPE_RECORD] = std::make_unique<json::RecordConverter>();
	json::converters[TYPE_VECTOR] = std::make_unique<json::VectorConverter>();
	}
