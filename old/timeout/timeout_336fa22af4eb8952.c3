// #target: macos-x64
module rawsplat;

int x;
macro void foo(...)
{
	$for var $i = 0; $i < $vaarg.len;  :
		x += $vaarg[$i] * $i;
	$endfor
}

fn void main()
{
	int[3] y = { 33, 44, 55 };
	foo(...y);
	foo(1, ...y);
	int[] z = &y;
	foo(...z[1..2]);
	foo(1, ...z[1..2], 5);
}