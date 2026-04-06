module std::test;

fn void main()
{
    char x = $$mask_to_int((bool[<8>]){ false, false, false, false, true, true, true, false });!
    $$trap();
}