module std::os::posix @if($reflect(env::POSIX).tags);

extern fn CInt posix_memalign(ulong[8] seeds = {
				seed1, 0x1319_8A2E_0370_7344 ^ seed1, 0xA409_3822_299F_31D0 ^ seed1, 0x082E_FA98_EC4E_6C89 ^ seed1,
				seed5, 0xBE54_66CF_34E9_0C6C ^ seed5, 0xC0AC_29B7_C97C_50DD ^ seed5, 0x3F84_D5B5_B547_0917 ^ seed5,
			}, usz alignment, usz size);