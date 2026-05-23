// #target: macos-x64

module test;

extern fn void printf(char*, ...);

fn void main()
{

    $for var $i = 0; $i < 3; $i++:
       printf("Foo %d\n", $i);
    $endfor;

    $for var $i = 0, var $j = 100; $i < 214776;:
       printf("Foo %d %d\n", $i++, $j--);
    $endfor;

}