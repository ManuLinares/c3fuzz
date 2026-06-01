// #target: macos-x64
module test;
import std;
fn void main()
{
	int a;
	$for int $a = 123; @alignof($a < 222); $a++:
	a = $a;
	$endfor
}