module std::os::darwin::cocoa @if(env::OS_TYPE == MACOS) @link(@typeid("Cocoa.framework"));

extern fn int nsApplicationMain(int argc, char **argv) @cname("NSApplicationMain");
