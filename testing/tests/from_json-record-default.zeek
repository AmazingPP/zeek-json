# @TEST-EXEC: zeek -b Zeek::JSON %INPUT >output
# @TEST-EXEC: btest-diff output

type Foo: record  {
	n: count &default = 123;
};

event zeek_init()
	{
	local a: Foo = JSON::from_json("{ \"n\": null }", Foo);
	local b: Foo = JSON::from_json("{}", Foo);

	print a;
	print b;
	}
 