#pragma once

#include <rapidjson/document.h>
#include <zeek/OpaqueVal.h>
#include <memory>
#include <string>

namespace zeek::json
	{

class JSONDocVal : public OpaqueVal
	{
public:
	JSONDocVal(rapidjson::Document);
	~JSONDocVal() noexcept = default;

	ValPtr DoClone(CloneState* state) override;

	auto& Get() { return doc; }
	const auto& Get() const { return doc; }

protected:
	JSONDocVal();

	DECLARE_OPAQUE_VALUE(JSONDocVal)

private:
	rapidjson::Document doc;
	};

using JSONDocValPtr = IntrusivePtr<JSONDocVal>;

class JSONValVal : public OpaqueVal
	{
public:
	static inline rapidjson::Value nil;

	JSONValVal(rapidjson::Value&, const JSONDocValPtr);
	~JSONValVal() noexcept = default;

	ValPtr DoClone(CloneState* state) override;

	auto& Get() { return val; }
	const auto& Get() const { return val; }
	auto& GetDoc() { return doc; }
	const auto& GetDoc() const { return doc; }

protected:
	JSONValVal();

	DECLARE_OPAQUE_VALUE(JSONValVal)

private:
	rapidjson::Value& val;
	const JSONDocValPtr doc;
	};

std::string stringify(const rapidjson::Value&);

	}
