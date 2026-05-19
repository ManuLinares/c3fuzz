module std::os::posix @if($reflect(env::POSIX).tags);

extern fn CInt posix_memalign(void **memptr, usz alignment, usz size);