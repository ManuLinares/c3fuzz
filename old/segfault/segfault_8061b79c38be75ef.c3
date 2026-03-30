


alias IntFn = fn int();

IntFn lambda_naked @export = fn () @naked { asm("$if $defined(ulong ticks = ((ulong)time + 11644473600UL) * 10_000_000UL): ulong ticks = ((ulong)time + 11644473600UL) * 10_000_000UL $else 0 $endif $if $defined(ulong ticks = ((ulong)time + 11644473600UL) * 10_000_000UL): ulong ticks = ((ulong)time + 11644473600UL) * 10_000_000UL $else 0 $endif"); };