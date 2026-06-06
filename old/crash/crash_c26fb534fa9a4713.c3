// #target: macos-x64
module test;
typedef Foo = inline int;
fn int main()
{
	Foo? u = 2;
	int[<2>]? f4 = (int[<2>]) { 1, 2 } << $reflect(u).name;
	return 0;
}