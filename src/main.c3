module c3fuzz;
import std, ts, tree_sitter_c3, libc;

const Duration TIMEOUT           = 5 * time::SEC;
const float SIMILARITY_THRESHOLD = 0.55;

enum CompilerResult
{
	CRASH,
	SEGFAULT,
	TIMEOUT,
	COMPILED
}

struct CrashInfo
{
	CompilerResult result;
	String key;
	String output;
	bool is_valid;
}

struct Stats
{
	Atomic{int} iters;
	Atomic{int} crashes;
	Atomic{int} segfaults;
	Atomic{int} timeouts;
}

struct FuzzerLogger (Logger)
{
	void* dummy; // / TODO: yeah
}

fn void FuzzerLogger.log(&self, LogPriority priority, LogCategory category, LogTag tag, String file, String function, int line, String fmt, any[] args) @dynamic
{
	String p_str;
	switch (priority)
	{
		case VERBOSE: p_str = "VERB";
		case DEBUG: p_str = "DEBUG";
		case INFO: p_str = "INFO";
		case WARN: p_str = "WARN";
		case ERROR: p_str = "ERROR";
		case CRITICAL: p_str = "CRIT";
	}
	String cat = log::get_category_name(category) ?? "?";
	String tag_str = ((String)tag[..]).trim("\x00");
	@stack_mem(512 ; Allocator smem)
	{
		DString msg;
		msg.init(smem, 256);
		msg.appendf(fmt, ...args);
		if (tag_str.len > 0)
		{
			io::printfn("[%s] [%s] [%s] %s", p_str, cat, tag_str, msg.str_view());
		}
		else
		{
			io::printfn("[%s] [%s] %s", p_str, cat, msg.str_view());
		}
	};
}

FuzzerLogger fuzzer_logger;
const LogCategory CAT_DISCOVERY = (LogCategory)101;
const LogCategory CAT_MUTATION  = (LogCategory)102;

struct ReportFinding
{
	String type;
	String key;
	String filename;
	String code;
	String output;
}

fn String escape_html(String s)
{
	DString res;
	res.init(tmem, s.len);
	foreach (char c : s)
	{
		if (c == '<')
		{
			res.append("&lt;");
		}
		else if (c == '>')
		{
			res.append("&gt;");
		}
		else if (c == '&')
		{
			res.append("&amp;");
		}
		else
		{
			res.append(c);
		}
	}
	return res.tcopy_str();
}

Stats global_stats;
Atomic{bool} should_quit;

HashSet{String} seen_error_locations;
Mutex seen_error_locations_mu;
tlocal String thread_build_dir;

HashSet{String} seen_failure_keys;
Mutex seen_failure_keys_mu;

List{String} unique_failure_sources;
Mutex unique_failure_mu;

List{String} snippet_pool;
HashSet{String} snippet_dedup;
Mutex snippet_pool_mu;
List{String} regression_pool;
Mutex regression_pool_mu;

bool is_bootstrapping = false;

tlocal uint[65536] similarity_counts;

fn void handle_sigint(CInt sig)
{
	should_quit.store(true);
}

fn int run_job(void* arg) => @pool_init(mem, 1024)
{
	int id = (int)(usz)arg;
	thread_build_dir = string::tformat("/tmp/c3fuzz_worker_%d", id);
	path::mkdir(thread_build_dir.to_tpath()!!)!!;

	int iters_since_clean = 0;

	while (!should_quit.load())
	{
		if (iters_since_clean++ > 1000)
		{
			DString cmd = dstring::temp("");
			cmd.appendf("rm -rf %s/*", thread_build_dir);
			(void)libc::system(cmd.str_view().zstr_tcopy());
			iters_since_clean = 0;
		}

		String source = generate_source();
		CompilerResult result = compile(source);

		if (is_bootstrapping) return 0;

		switch (result)
		{
			case SEGFAULT: global_stats.segfaults.add(1);
			case CRASH: global_stats.crashes.add(1);
			case TIMEOUT: global_stats.timeouts.add(1);
			case COMPILED:
		}
		global_stats.iters.add(1);
	}
	return 0;
}

List{String} global_seeds;

fn float source_similarity(String a, String b)
{
	if (a.len == 0 || b.len == 0) return a.len == b.len ? 1.0 : 0.0;
	if (a.len > 10000 || b.len > 10000) return 0.0;

	DString na = dstring::temp("");
	DString nb = dstring::temp("");
	foreach (char c : a) if (!ascii::is_space(c)) na.append(c);
	foreach (char c : b) if (!ascii::is_space(c)) nb.append(c);
	String sa = na.tcopy_str();
	String sb = nb.tcopy_str();

	if (sa.len < 2 || sb.len < 2) return sa == sb ? 1.0 : 0.0;

	usz pairs_a = sa.len - 1;
	usz pairs_b = sb.len - 1;

	mem::set(&similarity_counts, 0, uint::size * 65536);

	for (usz i = 0; i < pairs_a; i++)
	{
		ushort bigram = (ushort)sa[i] | ((ushort)sa[i + 1] << 8);
		similarity_counts[bigram]++;
	}

	int matches = 0;
	for (usz j = 0; j < pairs_b; j++)
	{
		ushort bigram = (ushort)sb[j] | ((ushort)sb[j + 1] << 8);
		if (similarity_counts[bigram] > 0)
		{
			matches++;
			similarity_counts[bigram]--;
		}
	}

	return (2.0 * (float)matches) / (float)(pairs_a + pairs_b);
}

fn bool is_duplicate_source(String source)
{
	unique_failure_mu.lock();
	defer unique_failure_mu.unlock();

	foreach (existing : unique_failure_sources)
	{
		if (source_similarity(source, existing) > SIMILARITY_THRESHOLD)
		{
			return true;
		}
	}

	unique_failure_sources.push(source.copy(mem));
	return false;
}

fn bool triage_failure(String key, String source, String folder, HashSet{String}* pool, Mutex* mu, CompilerResult result)
{
	bool is_new = false;
	mu.lock();
	if (!pool.contains(key))
	{
		pool.add(key.copy(mem));
		is_new = true;
	}
	mu.unlock();

	if (!is_new) return false;

	String final_source = source;
	if (!is_bootstrapping && result != TIMEOUT)
	{
		final_source = reduce_source(source, result, key);
	}

	bool too_similar = is_duplicate_source(final_source);

	if (folder == "segfault" || folder == "timeout")
	{
		if (too_similar) return true;
	}

	if (!is_bootstrapping)
	{
		String fname = string::tformat("%s/%s_%x.c3", folder, folder, fnv64a::hash((char[])final_source));
		(void)std::io::file::save(fname, final_source);
		log::warn("\n[NEW %s] Key: %s (Saved to %s)", folder, key, fname);
	}

	return true;
}

fn void collect_c3_files(std::io::path::Path p, List{String}* seeds) @local
{
	if (path::is_file(p))
	{
		String ext = p.extension() ?? "";
		if (ext == "c3" || ext == "c3t")
		{
			if (try String source = (String)std::io::file::load_temp(p.str_view()))
			{
				// For .c3t files: strip the trailing '/* #expect: ...' block
				if (ext == "c3t")
				{
					if (try idx = source.index_of("/* #expect:"))
					{
						source = source[:idx].trim();
					}
				}
				if (source.len > 0 && source.len < 20000)
				{
					seeds.push(source.copy(mem));
				}
			}
		}
		return;
	}

	if (path::is_dir(p))
	{
		if (try entries = path::ls(tmem, p, false, true))
		{
			foreach (f : entries)
			{
				if (try child = p.append(tmem, f.str_view()))
				{
					collect_c3_files(child, seeds);
				}
			}
		}
	}
}

fn void extract_snippets(String source, bool is_regression = false)
{
	TSParser* parser = ts::ts_parser_new();
	ts::ts_parser_set_language(parser, tree_sitter_c3::language());
	TSTree* tree = ts::ts_parser_parse_string(parser, null, source.zstr_tcopy(), (uint)source.len);
	TSNode root = ts::ts_tree_root_node(tree);

	NodeList nodes;
	nodes.init(mem);
	defer nodes.free();
	collect_smart_nodes(root, &nodes);

	Mutex* mu = is_regression ? &regression_pool_mu : &snippet_pool_mu;
	List{String}* pool = is_regression ? &regression_pool : &snippet_pool;

	mu.lock();
	foreach (n : nodes)
	{
		uint start = ts::ts_node_start_byte(n);
		uint end = ts::ts_node_end_byte(n);
		uint len = end - start;

		if (len > 30 && len < 400 && pool.len() < 10000)
		{
			String snip = source[start:len].trim();
			if (snip.len > 30 && !snippet_dedup.contains(snip))
			{
				String snip_copy = snip.copy(mem);
				snippet_dedup.add(snip_copy);
				pool.push(snip_copy);
				char* type_ptr = ts::ts_node_type(n);
				String type = type_ptr == null ? "unknown" : ((ZString)type_ptr).str_view();
				log::@category_scope(CAT_DISCOVERY)
				{
					log::debug("%s [%s] Snippet: [%s]", is_regression ? "GOLD" : "Smart", type, snip_copy);
				};
			}
		}
	}
	mu.unlock();

	ts::ts_tree_delete(tree);
	ts::ts_parser_delete(parser);
}

fn void collect_smart_nodes(TSNode node, NodeList* list, int depth = 0)
{
	if (depth > 256) return;
	if (!ts::ts_node_is_named(node)) return;

	char* type_ptr = ts::ts_node_type(node);
	if (type_ptr == null) return;
	String type = ((ZString)type_ptr).str_view();

	// If its a high-iq node, grab it and STOP recursing // Pruning
	uint kids = ts::ts_node_child_count(node);
	bool is_high_iq = false;

	if (type == "call_expression" || type == "binary_expression" || type == "if_statement" || type == "for_statement" || type == "assignment_expression" || type == "declaration")
	{
		if (kids >= 2) is_high_iq = true;
	}

	if (is_high_iq)
	{
		list.push(node);
		// pruning, don't grab the children of a node we already grabbed
		return;
	}

	// recurse to find logic clusters deeper down
	for (uint i = 0; i < kids; i++)
	{
		TSNode child = ts::ts_node_child(node, i);
		collect_smart_nodes(child, list, depth + 1);
	}
}

fn void gather_seeds(String dir)
{
	sz before = global_seeds.len();
	collect_c3_files(dir.to_tpath()!!, &global_seeds);
	log::info("Gathered %d seeds from %s", global_seeds.len() - before, dir);
}

fn void finalize_seeds()
{
	if (global_seeds.len() == 0)
	{
		log::warn("No seeds found! Using fallback.");
		global_seeds.push("import std; fn void main(){ io::printn(\"Fallback\"); }".copy(mem));
	}
	log::info("Total seeds available: %d", global_seeds.len());
}

fn String generate_source()
{
	if (global_seeds.len() == 0) return mutate_source("import std::io; fn void main(){}");
	return mutate_source(global_seeds[rand((int)global_seeds.len())]);
}

fn void bootstrap_crashes(String dir)
{
	List{String} files;
	files.init(mem);
	collect_c3_files(dir.to_tpath()!!, &files);
	foreach (source : files)
	{
		(void)compile(source);
	}
	files.free();
}

fn int main(String[] args)
{
	should_quit.store(false);
	libc::signal(libc::SIGINT, &handle_sigint);

	// logger -D FULL_LOG
	log::set_logger(&fuzzer_logger);
	log::set_category_name(CAT_DISCOVERY, "DISC");
	log::set_category_name(CAT_MUTATION, "MUT");
	bool verbose = $feature( FULL_LOG );
	int timeout;
	bool report_only = false;
	List{String} seed_dirs;
	seed_dirs.init(tmem);

	for (sz i = 1; i < args.len; i++)
	{
		String arg = args[i];
		if (arg == "-h" || arg == "--help")
		{
			io::printn(
				"Usage: c3fuzz [-v] [--report] [-t seconds] [-s seed_dir]\n" "\n" "  -v, --verbose  Show verbose output\n" "  --report       Just generate the HTML dashboard and exit\n" "  -t, --time     Stop after N seconds\n" "  -s, --seed     Add a directory to gather seeds from\n" "  -h, --help     Show this help\n"
			);
			return 0;
		}
		if (arg == "--report")
		{
			report_only = true;
		}
		else if (arg == "-v" || arg == "--verbose")
		{
			verbose = true;
		}
		else if (arg == "-t" || arg == "--time")
		{
			if (i + 1 < args.len)
			{
				if (try t = args[++i].to_int()) timeout = t;
			}
		}
		else if (arg == "-s" || arg == "--seed" || arg == "--s")
		{
			if (i + 1 < args.len) seed_dirs.push(args[++i]);
		}
		else if (try t = arg.to_int())
		{
			timeout = t;
		}
	}

	seen_error_locations.init(mem);
	seen_error_locations_mu.init()!!;
	seen_failure_keys.init(mem);
	seen_failure_keys_mu.init()!!;
	unique_failure_sources.init(mem);
	unique_failure_mu.init()!!;
	snippet_pool.init(mem);
	snippet_dedup.init(mem);
	snippet_pool_mu.init()!!;
	regression_pool.init(mem);
	regression_pool_mu.init()!!;

	if (report_only)
	{
		generate_report();
		return 0;
	}

	if (verbose)
	{
		log::set_priority_all(VERBOSE);
		log::info("Verbose mode enabled.");
	}
	else
	{
		log::set_priority_all(WARN);
		log::set_priority_for_category(CAT_DISCOVERY, WARN);
		log::set_priority_for_category(log::CATEGORY_APPLICATION, INFO);
	}

	global_seeds.init(mem);
	if (seed_dirs.len() == 0)
	{
		seed_dirs.push("crash");
		seed_dirs.push("segfault");
		seed_dirs.push("timeout");
	}

	foreach (dir : seed_dirs)
	{
		gather_seeds(dir);
	}
	finalize_seeds();

	(void)path::mkdir("crash".to_tpath()!!);
	(void)path::mkdir("segfault".to_tpath()!!);
	(void)path::mkdir("timeout".to_tpath()!!);

	// global_stats.iters.store(0);
	// global_stats.crashes.store(0);
	// global_stats.segfaults.store(0);

	thread_build_dir = "/tmp";

	log::info("Bootstrapping existing crashes...");
	is_bootstrapping = true;
	bootstrap_crashes("crash");
	bootstrap_crashes("segfault");
	bootstrap_crashes("timeout");

	// bootstrap_crashes("old/crash");
	// bootstrap_crashes("old/segfault");
	// bootstrap_crashes("old/timeout");
	is_bootstrapping = false;
	log::info("Bootstrap done. Known failures in memory: %d", unique_failure_sources.len() + seen_error_locations.len());

	// 1. Shuffle all gathered seeds yeah
	for (int i = (int)global_seeds.len() - 1; i > 0; i--)
	{
		int j = rand(i + 1);
		String tmp = global_seeds[i];
		global_seeds[i] = global_seeds[j];
		global_seeds[j] = tmp;
	}

	// 2. Extract snippets from the shuffled seeds
	log::info("Extracting unique crossover snippets (Random Sample)...");
	foreach (seed : global_seeds)
	{
		extract_snippets(seed, false);
		if (snippet_pool.len() >= 10000) break;
	}
	log::info("Smart pool ready: %d snippets.", snippet_pool.len());

	// 3. Extract lets call them GOLD snippets from test_suite (.c3 and .c3t)
	List{String} regression_seeds;
	regression_seeds.init(mem);
	collect_c3_files("test_suite".to_tpath()!!, &regression_seeds);
	log::info("Extracting GOLD snippets from test_suite (%d files)...", regression_seeds.len());
	foreach (seed : regression_seeds)
	{
		extract_snippets(seed, true);
		if (regression_pool.len() >= 15000) break;
	}
	regression_seeds.free();
	log::info("GOLD pool ready: %d snippets.", regression_pool.len());

	log::info("Fuzzer ready. Starting %d worker threads...", os::num_cpu());


	Thread[] threads = mem::new_array(Thread, os::num_cpu());
	foreach (usz idx, &t : threads)
	{
		thread::Thread.create(t, &run_job, (void*)idx)!!;
	}

	Time global_start = time::now();
	Time last_print = global_start;
	int last_iters = 0;

	while (true)
	{
		Time now = time::now();
		if (should_quit.load() || (timeout > 0 && now - global_start > timeout * time::SEC))
		{
			should_quit.store(true);
			break;
		}

		if (now - last_print >= time::SEC)
		{
			int iters = global_stats.iters.load();
			int segfaults = global_stats.segfaults.load();
			int crashes = global_stats.crashes.load();
			int timeouts = global_stats.timeouts.load();

			double speed = (double)(iters - last_iters) / (double)(now - last_print) * (double)time::SEC;
			io::printf("\rIters: %d | Speed: %.1f it/s | Crashes: %d | Segfaults: %d | Timeouts: %d", iters, speed, crashes, segfaults, timeouts);
			(void)io::stdout().flush();

			last_print = now;
			last_iters = iters;
			(void)libc::system("rm -rf /tmp/c3c*");
		}

		thread::sleep_ms(100);
	}

	log::info("\nFinished generating jobs. Waiting for threads to drain...");
	foreach (t : threads) t.join()!!;

	log::info("Final stats: Iters: %d, Crashes: %d, Segfaults: %d", global_stats.iters.load(), global_stats.crashes.load(), global_stats.segfaults.load());

	// generate_report(); //don't generate the report because something goes wrong
	// I suspect the unique crash hash in memory needs to be zeroed but I don't care
	return 0;
}

struct Rlimit { ulong rlim_cur; ulong rlim_max; }
extern fn CInt setrlimit(CInt resource, Rlimit* rlim);

fn CrashInfo get_crash_info(String input, bool check_only = false)
{
	// Disable core dumps to prevent the kernel from stalling the process
	// while writing memory to disk on a segfault. This does not always work
	// so I recommend `sudo sysctl -w kernel.core_pattern=core`
	const Rlimit RL   = { 0, 0 };
	const RLIMIT_CORE = 4;
	CInt rlim_res = setrlimit(RLIMIT_CORE, &RL);
	if (rlim_res != 0)
	{
		io::printfn("[DEBUG] setrlimit failed! code=%d, errno=%d", (int)rlim_res, (int)libc::errno());
	}

	String build_dir = thread_build_dir.len > 0 ? thread_build_dir : "/tmp";
	String[] cmd;
	if (check_only)
	{
		cmd = { "c3c", "compile-only", "-C", "-", "--build-dir", build_dir, "--obj-out", build_dir,
			"-O0", "-g0", "--threads", "1", "--no-entry" };
	}
	else
	{
		cmd = { "c3c", "compile-only", "-", "--build-dir", build_dir, "--obj-out", build_dir,
			"-O0", "-g0", "--threads", "1", "--no-entry" };
	}
	Process proc = process::spawn(cmd, INHERIT_ENV | STDERR_TO_STDOUT | ASYNC_OUTPUT)!!;
	defer proc.destroy();

	proc.write_stdin(input)!!;
	if (proc.stdin_file)
	{
		libc::fflush(proc.stdin_file);
		libc::fclose(proc.stdin_file);
		proc.stdin_file = null;
	}

	char[4 * 1024] stdout_buf;
	DString output;
	output.init(mem);
	defer output.free();
	Time start = time::now();

	// read output while the process is alive.
	CInt raw_status = 0;
	bool finished = false;
	while (true)
	{
		int res = posix::waitpid(proc.child, &raw_status, posix::WNOHANG);
		if (res == (int)proc.child)
		{
			finished = true;
			break;
		}
		if (res == -1) // waitpid failed
		{
			CInt err = libc::errno();
			if (err != Errno.EINTR) break;
		}

		if (time::now() - start > TIMEOUT)
		{
			proc.terminate()!!;
			return { TIMEOUT, string::tformat("TIMEOUT:%x", fnv64a::hash(input[..])), "", false };
		}

		if (should_quit.load())
		{
			proc.terminate()!!;
			return { COMPILED, "", "", false };
		}

		sz? len = proc.read_stdout(&stdout_buf, stdout_buf.len);
		if (try l = len)
		{
			if (l > 0) output.append(stdout_buf[:l]);
		}

		thread::sleep_ms(1);
	}

	if (!finished) posix::waitpid(proc.child, &raw_status, 0);

	while (true)
	{
		sz? len = proc.read_stdout(&stdout_buf, stdout_buf.len);
		if (try l = len)
		{
			if (l == 0) break;
			output.append(stdout_buf[:l]);
		}
		else
		{
			break;
		}
		thread::sleep_ms(1);
	}

	String out_str = output.str_view();

	bool valid = false;
	if (posix::wIFEXITED(raw_status) && posix::wEXITSTATUS(raw_status) == 0)
	{
		valid = true;
	}

	// Use raw_status for signal detection instead of the processed return_status from the process stdlib
	if (posix::wIFSIGNALED(raw_status))
	{
		CInt sig = posix::wTERMSIG(raw_status);
		// If it's a failure (1) or a signal was detected
		if (sig == libc::SIGINT || sig == libc::SIGKILL) return { COMPILED, "", "", false };
		if (sig == libc::SIGSEGV || sig == libc::SIGABRT)
		{
			String bt_key = "";
			if (try idx = out_str.index_of("LLVM ERROR: "))
			{
				String after = out_str[idx..];
				sz end = after.index_of("\n") ?? after.len;
				bt_key = after[:end].trim().copy(mem);
			}
			else
			{
				bt_key = string::tformat("SRC:%x", fnv64a::hash((char[])input)).copy(mem);
			}
			return { SEGFAULT, bt_key, out_str.copy(mem), false };
		}
		return { CRASH, string::tformat("SIG:%d", (int)sig).copy(mem), out_str.copy(mem), false };
	}

	if (out_str.contains("⚠️ The compiler encountered an unexpected error: "))
	{
		String func_key = "";
		if (try fidx = out_str.index_of("- Function: "))
		{
			String after = out_str[fidx + 12..];
			sz end = after.index_of("\n") ?? after.len;
			func_key = after[:end].trim();
		}
		String file_key = "";
		if (try sidx = out_str.index_of("- Source file: "))
		{
			String after = out_str[sidx + 15..];
			sz end = after.index_of("\n") ?? after.len;
			String full_path = after[:end].trim();
			if (try slash = full_path.rindex_of("/"))
			{
				file_key = full_path[slash + 1..];
			}
			else
			{
				file_key = full_path;
			}
		}
		String dedup_key = string::tformat("%s|%s", func_key, file_key);
		return { CRASH, dedup_key.copy(mem), out_str.copy(mem), false };
	}

	return { COMPILED, "", out_str, valid };
}

fn String reduce_source(String source, CompilerResult target_result, String target_key, Duration max_duration = (Duration)10)
{
	String current_best = source.copy(tmem);

	TSParser* parser = ts::ts_parser_new();
	ts::ts_parser_set_language(parser, tree_sitter_c3::language());

	Time start_time = time::now();
	bool changed = true;
	while (changed && !should_quit.load())
	{
		if (max_duration > (Duration)0 && time::now() - start_time > max_duration) break;

		changed = false;
		TSTree* tree = ts::ts_parser_parse_string(parser, null, current_best.zstr_tcopy(), (uint)current_best.len);
		TSNode root = ts::ts_tree_root_node(tree);

		NodeList nodes;
		nodes.init(mem);
		defer nodes.free();
		collect_nodes(root, &nodes);

		for (int i = (int)nodes.len() - 1; i >= 0; i--)
		{
			if (max_duration > (Duration)0 && time::now() - start_time > max_duration) break;

			TSNode node = nodes[i];
			if (!ts::ts_node_is_named(node)) continue;

			uint start = ts::ts_node_start_byte(node);
			uint end = ts::ts_node_end_byte(node);
			if (start == end) continue;

			DString test_ds = dstring::temp("");
			test_ds.append(current_best[0:start]);
			if (end < current_best.len) test_ds.append(current_best[end..]);
			String test_src = test_ds.tcopy_str();

			CrashInfo info = get_crash_info(test_src, true);
			if (info.result == COMPILED)
			{
				if (info.is_valid) info = get_crash_info(test_src, false);
			}

			// For silent segfaults and timeouts, the key is source-based and volatile.
			// ONLY require that the crash type matches during reduction.
			bool key_matches = (info.key == target_key);
			if (target_result == SEGFAULT || target_result == TIMEOUT) key_matches = true;

			if (info.result == target_result && key_matches)
			{
				current_best = test_src.copy(tmem);
				changed = true;
				break; // Restart with new tree
			}
		}
		ts::ts_tree_delete(tree);
	}

	ts::ts_parser_delete(parser);
	return current_best.copy(mem);
}

fn CompilerResult compile(String input)
{
	CrashInfo info = get_crash_info(input, true);

	if (info.result == COMPILED)
	{
		if (!info.is_valid) return COMPILED;
		info = get_crash_info(input, false);
	}

	// io::printfn("\n======> OUTPUT WAS: %s\n<======", info.output);
	// thread::sleep_ms(1000); // TODO: remove debug printout

	HashSet{String}* pool;
	Mutex* mu;
	String folder;

	switch (info.result)
	{
		case TIMEOUT:
			pool = &seen_failure_keys;
			mu = &seen_failure_keys_mu;
			folder = "timeout";
		case SEGFAULT:
			pool = &seen_failure_keys;
			mu = &seen_failure_keys_mu;
			folder = "segfault";
		case CRASH:
			pool = &seen_error_locations;
			mu = &seen_error_locations_mu;
			folder = "crash";
		case COMPILED:
			return COMPILED;
	}

	if (triage_failure(info.key, input, folder, pool, mu, info.result))
	{
		return info.result;
	}

	return COMPILED;
}

alias NodeList = List{TSNode};

fn void collect_nodes(TSNode node, NodeList* list, int depth = 0)
{
	if (depth > 256) return;
	uint kids = ts::ts_node_child_count(node);
	for (uint i = 0; i < kids; i++)
	{
		TSNode child = ts::ts_node_child(node, i);
		if (ts::ts_node_is_named(child)) list.push(child);
		collect_nodes(child, list, depth + 1);
	}
}

fn String get_node_text(String source, TSNode node)
{
	uint start = ts::ts_node_start_byte(node);
	uint end = ts::ts_node_end_byte(node);
	if (start >= end || end > source.len) return "";
	return source[start:end - start];
}

fn String mutate_source(String source)
{
	if (source.len == 0) return source;

	TSParser* parser = ts::ts_parser_new();
	ts::ts_parser_set_language(parser, tree_sitter_c3::language());

	TSTree* tree = ts::ts_parser_parse_string(parser, null, source.zstr_tcopy(), (uint)source.len);
	TSNode root = ts::ts_tree_root_node(tree);

	NodeList nodes;
	nodes.init(mem);
	defer nodes.free();
	collect_nodes(root, &nodes);

	if (nodes.len() == 0)
	{
		ts::ts_tree_delete(tree);
		ts::ts_parser_delete(parser);
		return source;
	}

	int[] weights = {
		0, 0, // Delete
		1, 1, // Duplicate
		2, 2, // Swap
		3, 3, // Suffix
		4, 4, 4, // Crossover
		5, // Op Mutation
		6, // Literal Torture
		7, // Result Abuse
		8, 8, // Reflection Abuse (.description / short_name)
		// 9, 10, // Edge Cases
		11, 11, // Generic Grinder
		12, 12, // Slice Torture
		13, 13, // Property/Swizzle
		14, // Scope Inversion
		15, 15, 15, 15, // GOLD before tests crossover
		16, 16, 16, 16, // Macro/CTE Torture
		17, 17, 17, 17, // Operator Overloading Torture
		18, 18, 18, // Type Reflection Torture
		19, 19 // Value Reflection Torture
		};
	int strategy = weights[rand(weights.len)];
	int idx = rand((int)nodes.len());
	TSNode target = nodes[idx];
	uint start = ts::ts_node_start_byte(target);
	uint end = ts::ts_node_end_byte(target);

	char* type_ptr = ts::ts_node_type(target);
	String type = type_ptr == null ? "" : ((ZString)type_ptr).str_view();

	DString result = dstring::temp("");
	switch (strategy)
	{
		case 0: // Delete Node
			result.append(source[0:start]);
			result.append(" ");
			if (end < source.len) result.append(source[end..]);
		case 1: // Duplicate Node
			String text = get_node_text(source, target);
			result.append(source[0:end]);
			result.append(" ");
			result.append(text);
			if (end < source.len) result.append(source[end..]);
		case 2: // Swap Node
			if (nodes.len() > 1)
			{
				int idx2 = rand((int)nodes.len());
				TSNode n2 = nodes[idx2];
				uint s2 = ts::ts_node_start_byte(n2);
				uint e2 = ts::ts_node_end_byte(n2);
				if (end < s2)
				{
					result.append(source[0:start]);
					result.append(get_node_text(source, n2));
					result.append(source[end:s2 - end]);
					result.append(get_node_text(source, target));
					if (e2 < source.len) result.append(source[e2..]);
				}
				else
				{
					result.append(source);
				}
			}
			else
			{
				result.append(source);
			}
		case 3: // Suffix Injection
			String[4] suffixes = { "~!", "~!!", "!!", "!" };
			result.append(source[0:end]);
			result.append(suffixes[rand(4)]);
			if (end < source.len) result.append(source[end..]);
		case 4: // Snippet Crossover
			String donor = "";
			snippet_pool_mu.lock();
			if (snippet_pool.len() > 0) donor = snippet_pool[rand((int)snippet_pool.len())];
			snippet_pool_mu.unlock();
			if (donor.len > 0)
			{
				result.append(source[0:start]);
				result.append(donor);
				if (end < source.len) result.append(source[end..]);
			}
			else
			{
				result.append(source);
			}
		case 5: // Op Mutation
			if (type == "binary_expression")
			{
				String[8] ops = { "+", "-", "*", "/", "&", "|", "<<", ">>" };
				result.append(source[0:start]);
				// This is a bit naive (assumes middle is op), but effective for fuzzing ok :/
				TSNode left = ts::ts_node_child(target, 0);
				TSNode right = ts::ts_node_child(target, 2);
				result.append(get_node_text(source, left));
				result.append(" ");
				result.append(ops[rand(8)]);
				result.append(" ");
				result.append(get_node_text(source, right));
				if (end < source.len) result.append(source[end..]);
			}
			else
			{
				result.append(source);
			}
		case 6: // Literal Torture
			if (type == "integer_literal")
			{
				result.append(source[0:start]);
				if (rand(2) == 0)
				{
					result.appendf("%d", rand(1000000));
				}
				else
				{
					result.append("0xFFFFFFFFFFFFFFFF");
				}
				if (end < source.len) result.append(source[end..]);
			}
			else
			{
				result.append(source);
			}
		case 7: // Result/Optional Abuse
			result.append(source[0:start]);
			if (rand(2) == 0)
			{
				result.append("(catch ");
				result.append(get_node_text(source, target));
				result.append(")");
			}
			else
			{
				result.append("@typeid(");
				result.append(get_node_text(source, target));
				result.append(")");
			}
			if (end < source.len) result.append(source[end..]);
		case 8: // Description Abuse
			result.append(source[0:start]);
			result.append(get_node_text(source, target));
			result.append(rand(2) == 0 ? ".description" : ".@short_name");
			if (end < source.len) result.append(source[end..]);
		case 9: // Segfault Edge Case
			result.clear();
			result.append("alias IntFn = fn int();\nIntFn asdf @export = fn () @naked { asm( \"$nsdasd\"); };\n");
		case 10: // crash Edge Case
			result.clear();
			result.append("fn void test(int... , int a){ } fn int main() { test(...(int[2]){ 88, 99 }, a: 123); return 0; }\n");
		case 11: // Generic Grinde
			{
				result.append(source[0:start]);
				String text = get_node_text(source, target);
				String[4] g_types = { "T", "Element", "Result", "K" };
				String g_name = g_types[rand(4)];

				if (type == "module_declaration")
				{
					sz start_mod = (text.index_of("module") ?? 0) + 6;
					sz end_mod = text.index_of(";") ?? long::max;
					if (start_mod < end_mod && end_mod != long::max)
					{
						result.append("module ");
						result.append(text[start_mod:end_mod - start_mod].trim());
						result.appendf(" <%s, OtherT>;", g_name);
					}
					else
					{
						result.append(text);
					}
				}
				else if (type == "func_definition" || type == "struct_definition")
				{
					result.append(text);
					result.appendf(" <%s>", g_name);
				}
				else if (type == "identifier")
				{
					result.append(text);
					if (rand(2) == 0)
					{
						result.append("{int, double}");
					}
					else
					{
						result.append("{MyType, float}");
					}
				}
				else
				{
					result.appendf("<* @require $assignable(1, %s) *> ", g_name);
					result.append(text);
				}
				if (end < source.len) result.append(source[end..]);
			}
		case 12: // Slice Torture
			{
				result.append(source[0:start]);
				String text = get_node_text(source, target);
				String[5] patterns = { "[^3..^1]", "[..^0]", "[-1..]", "[2..0]", "[^4..]" };
				result.append(text);
				result.append(patterns[rand(5)]);
				if (end < source.len) result.append(source[end..]);
			}
		case 13: // Property/Swizzle Torture
			{
				result.append(source[0:start]);
				String text = get_node_text(source, target);
				String[6] swizzles = { ".xyzw", ".rgba", ".x", ".rbx", ".xz", ".@type" };
				result.append(text);
				result.append(swizzles[rand(6)]);
				if (end < source.len) result.append(source[end..]);
			}
		case 14: // Scope Inversion
			{
				result.append("module injected_scope; \n");
				result.append("const dynamic_failure = ");
				result.append(get_node_text(source, target));
				result.append(";\n");
				result.append(source);
			}
		case 15: // maybe GOLD Crossover
			String donor = "";
			regression_pool_mu.lock();
			if (regression_pool.len() > 0) donor = regression_pool[rand((int)regression_pool.len())];
			regression_pool_mu.unlock();
			if (donor.len > 0)
			{
				result.append(source[0:start]);
				result.append(donor);
				if (end < source.len) result.append(source[end..]);
			}
			else
			{
				result.append(source);
			}
		case 16: // Macro/CTE Torture
			{
				result.append(source[0:start]);
				String text = get_node_text(source, target);

				if (type == "call_expression" && !text.starts_with("@"))
				{
					result.append("@");
					result.append(text);
				}
				else if (type == "identifier" && rand(2) == 0)
				{
					result.append("$");
					result.append(text);
				}
				else
				{
					String[12] builtins = {
						"@sizeof", "$typeof", "@alignof", "@kindof", "$expand",
						"$stringify", "$defined", "$vacount", "$vaconst",
						"$vaexpr", "$vasplat", "$reflect"
						};
					String b = builtins[rand(12)];
					if (rand(4) == 0)
					{
						result.appendf("$if $defined(%s): ", text);
						result.append(text);
						result.append(" $else 0 $endif");
					}
					else
					{
						result.append(b);
						result.append("(");
						result.append(text);
						result.append(")");
					}
				}
				if (end < source.len) result.append(source[end..]);
			}
		case 17: // Operator Overloading Torture
			{
				String struct_name = "FuzzedType";
				if (type == "struct_definition" || type == "bitstruct_definition")
				{
					for (uint i = 0; i < ts::ts_node_child_count(target); i++)
					{
						TSNode child = ts::ts_node_child(target, i);
						char* c_type_ptr = ts::ts_node_type(child);
						String c_type = c_type_ptr == null ? "" : ((ZString)c_type_ptr).str_view();
						if (c_type == "type_identifier" || c_type == "identifier")
						{
							String n = get_node_text(source, child).trim();
							if (n.len > 0) struct_name = n;
							break;
						}
					}
				}
				else
				{
					// If we are not on a struct, maybe inject a whole one
					result.append("struct FuzzedOpStruct { int a; double b; }\n");
					struct_name = "FuzzedOpStruct";
				}

				DString ops_code;
				ops_code.init(tmem);
				int choice = rand(8);
				switch (choice)
				{
					case 0: // Container basic
						ops_code.appendf("fn int %s.get(&self, usz i) @operator([]) { return 0; }\n", struct_name);
						ops_code.appendf("fn usz %s.len(&self) @operator(len) { return 1; }\n", struct_name);
					case 1: // Set & Ref
						ops_code.appendf("fn void %s.set(&self, usz i, int v) @operator([]=) { }\n", struct_name);
						ops_code.appendf("fn int* %s.get_ref(&self, usz i) @operator(&[]) { return null; }\n", struct_name);
					case 2: // Arithmetic
						ops_code.appendf("fn %s %s.add(self, %s other) @operator(+) { return self; }\n", struct_name, struct_name, struct_name);
						ops_code.appendf("fn %s %s.sub(self, double d) @operator_s(-) { return self; }\n", struct_name, struct_name);
					case 3: // Symmetric/Reverse
						ops_code.appendf("macro %s %s.mul_d(self, double d) @operator_s(*) { return self; }\n", struct_name, struct_name);
						ops_code.appendf("macro %s %s.div_r(self, int i) @operator_r(/) { return self; }\n", struct_name, struct_name);
					case 4: // Comparison & Comparison (new < operator)
						ops_code.appendf("fn bool %s.eq(self, %s other) @operator(==) { return true; }\n", struct_name, struct_name);
						ops_code.appendf("fn bool %s.lt(self, %s other) @operator(<) { return false; }\n", struct_name, struct_name);
					case 5: // Bitwise (should error on bitstructs? lets test)
						ops_code.appendf("fn %s %s.xor(self, %s other) @operator(^) { return self; }\n", struct_name, struct_name, struct_name);
						ops_code.appendf("fn %s %s.shl(self, int i) @operator(<<) { return self; }\n", struct_name, struct_name);
					case 6: // Combined assignment
						ops_code.appendf("fn %s %s.add_ass(&self, %s other) @operator(+=) { return *self; }\n", struct_name, struct_name, struct_name);
					case 7: // Implicit casting matches
						ops_code.appendf("fn %s %s.f(self, float f) @operator(-) { return self; }\n", struct_name, struct_name);
						ops_code.appendf("fn %s %s.d(self, double d) @operator(-) { return self; }\n", struct_name, struct_name);
				}

				result.append(source[0:end]);
				result.append("\n");
				result.append(ops_code.str_view());
				if (end < source.len) result.append(source[end..]);

				result.appendf("\nfn void fuzzed_op_test_%d(%s s) { \n", rand(1000), struct_name);
				result.append("  var x = s; \n");
				switch (choice)
				{
					case 0: result.append("  int x0 = x[0]; foreach (v : x) { (void)v; } \n");
					case 1: result.append("  x[0] = 1; var r = &x[0]; \n");
					case 2: result.append("  x = x + x; x = x - 1.0; x = 1.0 - x; \n");
					case 3: result.append("  x = x * 2.0; x = 2.0 * x; x = 10.0 / x; \n");
					case 4: result.append("  bool b = (x == x) || (x != x) || (x < x);\n");
					case 5: result.append("  x = x ^ x; x = x << 1; \n");
					case 6: result.append("  x += x; \n");
					case 7: result.append("  x = x - 1.0f; x = x - 2.0; x = x - 3; // possible ambiguity error \n");
				}
				result.append("}\n");
			}
		case 18: // Type Reflection Torture
			{
				result.append(source[0:start]);
				String text = get_node_text(source, target);
				String[10] props = { "::size", "::alignment", "::has_equals", "::members", "::len", "::max", "::min", "::kind", "::values", "::get_tag()" };
				result.append(text);
				result.append(props[rand(10)]);
				if (end < source.len) result.append(source[end..]);
			}
		case 19: // Value Reflection Torture
			{
				result.append(source[0:start]);
				String text = get_node_text(source, target);
				String[5] props = { ".name", ".size", ".offset", ".alignment", ".tags" };
				result.append("$reflect(");
				result.append(text);
				result.append(")");
				result.append(props[rand(5)]);
				if (end < source.len) result.append(source[end..]);
			}
		default:
			result.append(source);
	}

	ts::ts_tree_delete(tree);
	ts::ts_parser_delete(parser);

	String mutated = result.copy_str(mem);
	if (false) io::printfn("--- mutation ---\n%s\n--- end of mutation ---", mutated); //DEBUG! TODO!
	return mutated.len > 0 ? mutated : source;
}
