bitstruct Foo : long
{
	int a : 2..4;
	uint b: 5..10;
}
fn int main()
{
	Foo? d = { 1, 11 };
	$defined(Foo::members[0].set(d, 3));
	return 0;
}