#pragma once

#include <zeek/plugin/Plugin.h>

#include "JSON.h"

namespace zeek::plugin
	{
namespace Zeek_JSON
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;

	void InitPreScript() override;
	};

extern Plugin plugin;

	}
	}
