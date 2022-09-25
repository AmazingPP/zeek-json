# @TEST-EXEC-FAIL: zeek -b Zeek::JSON %INPUT >output 2>err
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff err

type Foo: record  {
	n: count;
};

event zeek_init()
	{
	local a: Foo = JSON::from_json("{ \"n\": null }", Foo);
	local b: Foo = JSON::from_json("{}", Foo);

	print a;
	print b;
	}
