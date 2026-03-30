


alias IntFn = fn int();

IntFn lambda_naked @export = fn () @naked { asm("$stringify(ulong ticks = ((ulong)time + 11644473600UL) * 10_000_000UL)"); };