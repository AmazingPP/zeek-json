#include "config.h"
#include "Plugin.h"

namespace zeek::plugin::Zeek_JSON { Plugin plugin; }

using namespace zeek::plugin::Zeek_JSON;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Zeek::JSON";
	config.description = "TODO: Insert description";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
