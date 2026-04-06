module std::test;

fn void main()
{
    String[*] a = (String[1]) { "hello" } +++ (String[1]) { " world" };!
    $$trap();
}