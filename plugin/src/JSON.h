#pragma once

#include <array>
#include <memory>
#include <zeek/Val.h>
#include <rapidjson/document.h>

namespace zeek::json
	{

#define CONVERTER_CLASS_DECL(name) class name final : public Converter 	\
	{																				\
public:																				\
	bool Check(const rapidjson::Value& val) const override;							\
	ValPtr Exec(const rapidjson::Value& val, const TypePtr& type) const override;	\
	};

class Converter
	{
public:
	Converter() = default;
	virtual ~Converter() = default;

	virtual bool Check(const rapidjson::Value& val) const;

	virtual ValPtr Exec(const rapidjson::Value& val, const TypePtr& type) const;
	};

CONVERTER_CLASS_DECL(BoolConverter)
CONVERTER_CLASS_DECL(IntConverter)
CONVERTER_CLASS_DECL(CountConverter)
CONVERTER_CLASS_DECL(DoubleConverter)
CONVERTER_CLASS_DECL(StringConverter)
CONVERTER_CLASS_DECL(RecordConverter)
CONVERTER_CLASS_DECL(VectorConverter)

inline std::array<std::unique_ptr<Converter>, NUM_TYPES> converters;

ValPtr from_json(const StringVal* json, const TypeVal& type);

	}
