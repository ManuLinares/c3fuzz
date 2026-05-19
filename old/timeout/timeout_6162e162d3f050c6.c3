module libc @if(env::DARWIN ||| env::BSD_FAMILY);

const CInt SIGIOT = 6;
const CInt SIGEMT = 7;
bool is_def2 = $defined($$FUNCTION);
const CInt SIGPROF = 27;
const CInt SIGINFO = 29;
const CInt SIGTHR = 32;
