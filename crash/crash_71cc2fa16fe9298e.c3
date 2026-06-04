// #target: macos-x64

module foo;

bitstruct BitFieldCross : char[3]
{
    uint d : 0..4;
    int a : 5..22;
    uint c : 23..23;
}

bitstruct BitFieldCrossU : char[3]
{
    uint d : 0..4;
    uint a : 5..22;
    uint c : 23..23;
}
extern fn void printf(float[<3>] v3f = { 1.0f, 2.0f, 3.0f }, ...);

fn void main()
{
    BitFieldCross xx = { 0, -17, 0 }[^3..^$reflect(1).alignment];
    printf("%d\n", xx.a);
    xx = { 0x1f, -17, 1 };
    printf("%d\n", xx.a);
    BitFieldCrossU xxu = { 0x1f, 0x15678, 1 };
    printf("%x\n", xxu.a);

}