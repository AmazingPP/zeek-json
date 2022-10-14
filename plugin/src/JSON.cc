#include "JSON.h"

#include <broker/data.hh>
#include <broker/error.hh>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <string.h>

#include "Converter.h"

#if ZEEK_VERSION_NUMBER > 50000
namespace caf = broker;
#endif

namespace zeek::json
	{

static auto json_doc_type = make_intrusive<OpaqueType>("json_doc");
static auto json_val_type = make_intrusive<OpaqueType>("json_val");

JSONDocVal::JSONDocVal(rapidjson::Document arg_d) : OpaqueVal(json_doc_type), doc(std::move(arg_d))
	{
	}

JSONDocVal::JSONDocVal() : OpaqueVal(json_doc_type), doc() { }

IMPLEMENT_OPAQUE_VALUE(JSONDocVal)

ValPtr JSONDocVal::DoClone(CloneState* state)
	{
	rapidjson::Document d;
	d.CopyFrom(doc, d.GetAllocator());

	return state->NewClone(this, make_intrusive<JSONDocVal>(std::move(d)));
	}

broker::expected<broker::data> JSONDocVal::DoSerialize() const
	{
	return {stringify(doc)};
	}

bool JSONDocVal::DoUnserialize(const broker::data& data)
	{
	auto d = caf::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	auto s = caf::get_if<std::string>(&(*d)[0]);
	if ( ! s )
		return false;

	rapidjson::ParseResult ok = doc.Parse(s->c_str(), s->length());
	if ( ! ok )
		return false;

	return true;
	}

JSONValVal::JSONValVal(rapidjson::Value& arg_v, JSONDocValPtr arg_d)
	: OpaqueVal(json_val_type), val(arg_v), doc(arg_d)
	{
	}

JSONValVal::JSONValVal() : OpaqueVal(json_val_type), val(nil), doc() { }

IMPLEMENT_OPAQUE_VALUE(JSONValVal)

ValPtr JSONValVal::DoClone(CloneState* state)
	{
	return state->NewClone(this, make_intrusive<JSONValVal>(val, doc));
	}

broker::expected<broker::data> JSONValVal::DoSerialize() const
	{
	return broker::make_error(broker::ec::invalid_data, "cannot serialize json value handles");
	}

bool JSONValVal::DoUnserialize(const broker::data& data)
	{
	return false;
	}

std::string stringify(const rapidjson::Value& val)
	{
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<decltype(buffer)> writer(buffer);
	val.Accept(writer);

	return {buffer.GetString(), buffer.GetLength()};
	}

	}
