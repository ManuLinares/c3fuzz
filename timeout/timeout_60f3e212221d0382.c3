// #target: macos-x64
module test;
import std;

bitstruct Some : char
{
	char v : 0 .. 4;
}

const int[8] SOME_MAP = some_macro();

macro some_macro()
{
	Some $s = { 8 };
	int[8] $map;
	$for var $i = 0; $defined($i < 4); $i++:
		$s = { .v = $s.v >> 1 };
		$map[$s.v] = 1;
	$endfor;
	return $map;
}