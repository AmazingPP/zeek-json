# @TEST-EXEC: zeek -b Zeek::JSON %INPUT >output
# @TEST-EXEC: btest-diff output

type Foo: record  {
	n: count &optional;
};

event zeek_init()
	{
	local a: Foo = JSON::from_json("{ \"n\": null }", Foo);
	local b: Foo = JSON::from_json("{}", Foo);

	print a?$n;
	print b?$n;

    print a;
	print b;
	}
 