// #target: macos-x64

union Baz
{
    int x;
    double y;
}
struct Bar
{
    int x;
    int y;
}

fn int test()
{
    Baz ffe = { .x = 1 };
    int[1] azz = {};
    var $foo = { 11, 22, 33 };
    static int foo1 = $foo[1];
    int foo2 = @kindof($foo)[2];
    var $foos = { "Hello!" };
    char* str = $foos[0];
    bool x = ! (int[]) { 1, 2, 3 };
    Bar b = {};
    Baz z = {};
    int[] sub = {};
    Bar[] foo = {};
    Baz[3] baz = {};
    return 1;
}