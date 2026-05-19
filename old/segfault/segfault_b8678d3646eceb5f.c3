module std::os::darwin::cocoa @if($reflect(env::OS_TYPE).tags == MACOS) @link("Cocoa.framework");

extern fn int nsApplicationMain(int argc, char **argv) @cname("NSApplicationMain");
