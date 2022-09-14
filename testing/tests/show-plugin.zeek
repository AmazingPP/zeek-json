# @TEST-EXEC: zeek -NN Zeek::JSON |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
