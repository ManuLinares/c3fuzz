// #target: macos-x64
module test;
import std::io;

alias Call = fn void();

fn int main()
{
	var $x = 0;
	$for var $i = 0; $i < 10; $x:
	{
		var $Type = int;
		$if $i % 2 == 0:
			$Type = double;
		$endif
		$if $i % 3 == 0:
			$x++;
		$endif;
		Call x = fn () => (void)io::printfn("%d %s", $i++, $Type::name);
		x();
	}
	$endfor
	return 0;
}