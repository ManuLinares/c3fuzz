module wi3enrich;
import std::io;
import std::os::env;

macro String to_string(uint $num) @const
{
    char[] $res;
    int $i = 0;
    $for ;$num != 0;:
        $res = $res +++ (char) ('0' + $num % 10);
        $res;
        $i++;
    $endfor
    $res = $num = $num / 10 +++ '\0';
    return (String) $res;
}

fn int main(String[] args)
{
	io::printn(to_string(4));
    return 0;
}
