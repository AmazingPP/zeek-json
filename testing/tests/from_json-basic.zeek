# @TEST-EXEC: zeek -b Zeek::JSON %INPUT >output
# @TEST-EXEC: btest-diff output

type Foo: record  {
    hello: string;
    t: bool;
    f: bool;
	n: count &optional;
	i: int;
	pi: double;
	a: string_vec;
};

event zeek_init()
	{
	local json = "{ \"hello\" : \"world\", \"t\" : true , \"f\" : false, \"n\": null, \"i\":123, \"pi\": 3.1416, \"a\":[\"1\", \"2\", \"3\", \"4\"] }";
	local a: Foo = JSON::from_json(json, Foo);

	print a;

	a$hello = "json";
	a$t = F;
	a$f = T;
	a$n = 9223372036854775808;
	a$i = -10;
	a$pi = 3.14;
	a$a = ["5", "6", "7", "8"];

	print a;
	}
 