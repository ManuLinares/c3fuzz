


alias IntFn = fn int();

IntFn lambda_naked @export = fn () @naked { asm("<* @require $assignable(1, T) *> ret"); };