// #target: macos-x64
module test;

alias IntFn = fn int();
IntFn lambda @export = fn () => 1;
IntFn lambda_naked @export = fn () @naked { asm("$vaexpr(ret)"); };