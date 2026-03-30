


alias IntFn = fn int();

IntFn lambda_naked @export = fn () @naked { asm("$vasplat(QueueEntry* entry = linkedblockingqueue_unlink_head(self))"); };