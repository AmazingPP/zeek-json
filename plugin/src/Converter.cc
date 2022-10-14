#include "Converter.h"

#include <rapidjson/error/en.h>
#include <zeek/Attr.h>
#include <zeek/Expr.h>
#include <zeek/Reporter.h>
#include <map>

namespace zeek::json
	{

inline static ValPtr BuildVal(const rapidjson::Value& val, const TypePtr& type)
	{
	if ( val.IsNull() )
		return Val::nil;

	auto&& converter = converters[type->Tag()];
	if ( ! converter->Check(val) )
		{
		reporter->Error("Unmatched type: %s!", type->GetName().c_str());
		return Val::nil;
		}

	return converter->Exec(val, type);
	}

bool Converter::Check(const rapidjson::Value& val) const
	{
	return true;
	}

ValPtr Converter::Exec(const rapidjson::Value& val, const TypePtr& type) const
	{
	reporter->Error("Unsupported type: %s!", type->GetName().c_str());
	return Val::nil;
	}

bool BoolConverter::Check(const rapidjson::Value& val) const
	{
	return val.IsBool();
	}

ValPtr BoolConverter::Exec(const rapidjson::Value& val, const TypePtr& _) const
	{
	return val_mgr->Bool(val.GetBool());
	}

bool IntConverter::Check(const rapidjson::Value& val) const
	{
	return val.IsInt64();
	}

ValPtr IntConverter::Exec(const rapidjson::Value& val, const TypePtr& _) const
	{
	return val_mgr->Int(val.GetInt64());
	}

bool CountConverter::Check(const rapidjson::Value& val) const
	{
	return val.IsUint64();
	}

ValPtr CountConverter::Exec(const rapidjson::Value& val, const TypePtr& _) const
	{
	return val_mgr->Count(val.GetUint64());
	}

bool DoubleConverter::Check(const rapidjson::Value& val) const
	{
	return val.IsDouble();
	}

ValPtr DoubleConverter::Exec(const rapidjson::Value& val, const TypePtr& _) const
	{
	return make_intrusive<DoubleVal>(val.GetDouble());
	}

bool StringConverter::Check(const rapidjson::Value& val) const
	{
	return val.IsString();
	}

ValPtr StringConverter::Exec(const rapidjson::Value& val, const TypePtr& _) const
	{
	return make_intrusive<StringVal>(val.GetStringLength(), val.GetString());
	}

bool RecordConverter::Check(const rapidjson::Value& val) const
	{
	return val.IsObject();
	}

ValPtr RecordConverter::Exec(const rapidjson::Value& val, const TypePtr& type) const
	{
	auto rt = type->AsRecordType();
	auto rv = make_intrusive<RecordVal>(IntrusivePtr{NewRef{}, rt});
	for ( int i = 0; i < rt->NumFields(); ++i )
		{
		auto td_i = rt->FieldDecl(i);
		bool has_member = val.HasMember(td_i->id);
		bool member_is_null = has_member ? val[td_i->id].IsNull() : true;

		if ( ! has_member || member_is_null )
			{
			if ( auto def = td_i->GetAttr(detail::ATTR_DEFAULT).get(); def )
				{
				rv->Assign(i, def->GetExpr()->Eval(nullptr));
				continue;
				}

			if ( ! td_i->GetAttr(detail::ATTR_OPTIONAL) )
				reporter->Error("%s field \"%s\" is null or missing!", type->GetName().c_str(),
				                td_i->id);

			rv->Assign(i, Val::nil);
			continue;
			}

		rv->Assign(i, BuildVal(val[td_i->id], rt->GetFieldType(i)));
		}

	return rv;
	}

bool VectorConverter::Check(const rapidjson::Value& val) const
	{
	return val.IsArray();
	}

ValPtr VectorConverter::Exec(const rapidjson::Value& val, const TypePtr& type) const
	{
	auto vt = type->AsVectorType();
	auto vv = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, vt});
	unsigned int i = 0;
	for ( const auto& item : val.GetArray() )
		{
		vv->Assign(i++, BuildVal(item, vt->Yield()));
		}

	return vv;
	}

ValPtr from_json(StringVal* json, const zeek::Type* type)
	{
	rapidjson::Document doc;
	rapidjson::ParseResult ok = doc.Parse(json->CheckString(), json->Len());

	if ( ! ok )
		{
		reporter->Error("JSON parse error: %s (%lu)", rapidjson::GetParseError_En(ok.Code()),
		                ok.Offset());
		return Val::nil;
		}

	return BuildVal(doc, type->AsTypeType()->GetType());
	}

ValPtr build_zeek_val(const rapidjson::Value& json_val)
	{
	switch ( json_val.GetType() )
		{
		case rapidjson::kFalseType:
			return val_mgr->False();
		case rapidjson::kTrueType:
			return val_mgr->True();
		case rapidjson::kObjectType:
			{
			auto record_types = new type_decl_list();
			std::vector<ValPtr> record_vals;

			for ( const auto& m : json_val.GetObject() )
				{
				auto name = util::copy_string(m.name.GetString());
				auto value = build_zeek_val(m.value);

				record_types->push_back(new TypeDecl(name, value->GetType()));
				record_vals.emplace_back(std::move(value));
				}

			auto rv = make_intrusive<RecordVal>(make_intrusive<RecordType>(record_types));
			for ( size_t i = 0; i < record_vals.size(); ++i )
				rv->Assign(i, std::move(record_vals[i]));

			return rv;
			}
		case rapidjson::kArrayType:
			{
			static auto any_vec = make_intrusive<VectorType>(base_type(TYPE_ANY));
			if ( json_val.Empty() )
				return make_intrusive<VectorVal>(any_vec);

			std::vector<ValPtr> vector_vals;
			for ( const auto& item : json_val.GetArray() )
				vector_vals.emplace_back(build_zeek_val(item));

			auto vv = make_intrusive<VectorVal>(
				make_intrusive<VectorType>(vector_vals[0]->GetType()));
			vv->Resize(json_val.Size());
			for ( size_t i = 0; i < vector_vals.size(); ++i )
				vv->Assign(i, std::move(vector_vals[i]));

			return vv;
			}
		case rapidjson::kStringType:
			return make_intrusive<StringVal>(json_val.GetStringLength(), json_val.GetString());
		case rapidjson::kNumberType:
			{
			if ( json_val.IsUint64() )
				return val_mgr->Count(json_val.GetUint64());
			else if ( json_val.IsDouble() )
				return make_intrusive<DoubleVal>(json_val.GetDouble());
			else
				return val_mgr->Int(json_val.GetInt64());
			}

		default:
			break;
		}

	return val_mgr->EmptyString();
	}

	}