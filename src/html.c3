module c3fuzz;
import std, ts, libc;

fn bool source_is_text(String s)
{
	foreach (char c : s)
	{
		if (c < 0x09) return false; // Below TAB
		if (c == 0x0b || c == 0x0c) return false; // VT, FF
		if (c >= 0x0e && c < 0x20) return false; // Control chars except CR/LF/TAB
		if (c == 0x7f) return false; // DEL
		if (c > 0x7f) return false; // Non-ASCII (binary)
	}
	return true;
}


fn void generate_report()
{
	log::info("📊 Generating Fuzzer Dashboard...");

	List{ReportFinding} findings;
	findings.init(mem);

	int crash_count = 0;
	int segfault_count = 0;
	int timeout_count = 0;

	HashSet{String} report_dedup;
	report_dedup.init(tmem);
	List{String} report_sources;
	report_sources.init(tmem);

	String[] folders = { "crash", "segfault", "timeout" };
	foreach (folder_name : folders)
	{
		Path folder_path = folder_name.to_tpath()!!;
		if (try entries = path::ls(tmem, folder_path, false, true))
		{
			foreach (f_path : entries)
			{
				String f = f_path.path_string;
				if (!f.ends_with(".c3")) continue;

				if (try p = folder_path.tappend(f))
				{
					if (try source = (String)std::io::file::load_temp(p.path_string))
					{
						// Skip noisy assembly-related findings in the dashboard
						if (source.contains("asm(\""))
						{
							continue;
						}

						CrashInfo res = get_crash_info(source);

						if (res.result == COMPILED)
						{
							// Bug was fixed (or was flaky) - retire it to old/
							String old_dir = string::tformat("old/%s", folder_name);
							(void)path::mkdir("old".to_tpath()!!);
							(void)path::mkdir(old_dir.to_tpath()!!);
							String old_path = string::tformat("%s/%s", old_dir, f);
							(void)libc::rename(p.path_string.zstr_tcopy(), old_path.zstr_tcopy());
							log::info("Retired non-reproducing %s: %s -> %s", folder_name, f, old_path);
							continue;
						}

						String reduced_source = source;
						if (res.result == CRASH)
						{
							reduced_source = reduce_source(source, res.result, res.key, 5 * time::SEC);
						}

						bool is_duplicate = false;
						if (report_dedup.contains(res.key))
						{
							is_duplicate = true;
						}
						else
						{
							foreach (existing : report_sources)
							{
								if (source_similarity(reduced_source, existing) > SIMILARITY_THRESHOLD)
								{
									is_duplicate = true;
									break;
								}
							}
						}

						if (is_duplicate)
						{
							String old_dir = string::tformat("old/duplicate_%s", folder_name);
							(void)path::mkdir("old".to_tpath()!!);
							(void)path::mkdir(old_dir.to_tpath()!!);
							String old_path = string::tformat("%s/%s", old_dir, f);
							(void)libc::rename(p.path_string.zstr_tcopy(), old_path.zstr_tcopy());
							log::info("Retired duplicate bug %s: %s -> %s (Key: %s)", folder_name, f, old_path, res.key);
							continue;
						}

						report_dedup.add(res.key.copy(tmem));
						report_sources.push(reduced_source.copy(tmem));

						String target_folder;
						switch (res.result)
						{
							case TIMEOUT:  { target_folder = "timeout";  timeout_count++;  }
							case SEGFAULT: { target_folder = "segfault"; segfault_count++; }
							case CRASH:    { target_folder = "crash";    crash_count++;    }
							default: unreachable();
						}

						String final_filename = f;
						if (target_folder != folder_name)
						{
							String new_f = f;
							if (try idx = f.index_of("_"))
							{
								new_f = string::tformat("%s%s", target_folder, f[idx..]);
							}

							String new_path = string::tformat("%s/%s", target_folder, new_f);
							(void)libc::rename(p.path_string.zstr_tcopy(), new_path.zstr_tcopy());
							log::info("Reclassified %s -> %s: %s -> %s", folder_name, target_folder, f, new_f);
							final_filename = new_f;
						}

						findings.push(
							(ReportFinding) {
								.type = target_folder.to_upper_copy(mem),
								.key = final_filename.copy(mem),
								.filename = final_filename.copy(mem),
								.code = reduced_source.trim(),
								.output = res.output
							}
						);
						log::info("Added %s: %s to report", target_folder, final_filename);
					}
				}
			}
		}
	}


	if (findings.len() == 0)
	{
		log::info("No reproducible findings. Generating 'All Clear' dashboard.");
	}

	DString html;
	html.init(mem, 1024 * 64);

	html.append(
		`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>C3 Fuzzer Dashboard</title>
	<meta name="description" content="C3 Fuzzer Dashboard interface">
	<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">
	<meta name="theme-color" content="#0f172a" media="(prefers-color-scheme: dark)">

	<link rel="icon" type="image/svg+xml" href="logo.svg">
	<link rel="apple-touch-icon" href="logo.svg">

	<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.30.0/prism.min.js"></script>
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism-themes/1.9.0/prism-vsc-dark-plus.min.css" />

	<style>
		:root {
			--bg-color: #0d1117;
			--card-bg: #161b22;
			--accent-color: #58a6ff;
			--text-primary: #c9d1d9;
			--text-secondary: #8b949e;
			--border-color: #30363d;
			--code-bg: #0d1117;

			/* Font Stacks */
			--font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;
			--font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;

			/* GitHub Dark Code Colors */
			--syntax-keyword: #ff7b72;
			--syntax-string: #a5d6ff;
			--syntax-comment: #8b949e;
			--syntax-function: #d2a8ff;
			--syntax-number: #79c0ff;
			--syntax-operator: #ff7b72;
			--syntax-constant: #79c0ff;
			--syntax-attr: #ffa198;
		}

		body {
			background-color: var(--bg-color);
			color: var(--text-primary);
			font-family: var(--font-sans);
			margin: 0;
			padding: 40px;
			line-height: 1.5;
		}

		.container {
			max-width: 1000px;
			margin: 0 auto;
		}

		header {
			text-align: center;
			margin-bottom: 40px;
			padding: 40px 20px;
			background: radial-gradient(circle at 50% 100%, rgba(88, 166, 255, 0.05) 0%, transparent 70%);
		}

		h1 {
			font-size: 1.8rem;
			font-weight: 700;
			letter-spacing: -0.02em;
			margin: 0;
			color: #f0f6fc;
		}

		.subtitle {
			color: var(--text-secondary);
			font-size: 1rem;
			margin-top: 8px;
			font-weight: 400;
		}

		.stats {
			margin-top: 20px;
			display: flex;
			justify-content: center;
			gap: 12px;
		}

		.badge {
			display: flex;
			align-items: center;
			gap: 6px;
			padding: 4px 12px;
			border-radius: 100px;
			font-size: 0.8rem;
			font-weight: 600;
			letter-spacing: 0.01em;
			text-decoration: none;
			transition: all 0.2s ease;
		}

		.badge.crash {
			background: rgba(244, 63, 94, 0.15);
			border: 1px solid rgba(244, 63, 94, 0.25);
			color: #ffa198;
		}

		.badge.segfault {
			background: rgba(210, 168, 255, 0.1);
			border: 1px solid rgba(210, 168, 255, 0.2);
			color: #d2a8ff;
		}

		.badge.zero {
			background: rgba(46, 160, 67, 0.1) !important;
			border-color: rgba(46, 160, 67, 0.2) !important;
			color: #3fb950 !important;
			cursor: default;
		}

		#repro-findings {
			background: var(--card-bg);
			border: 1px solid var(--border-color);
			border-radius: 12px;
			padding: 30px 40px;
			box-shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.3);
		}

		h2 {
			font-size: 1.3rem;
			border-bottom: 1px solid var(--border-color);
			padding-bottom: 10px;
			margin-top: 40px;
			font-weight: 600;
			color: #f0f6fc;
			scroll-margin-top: 40px;
		}

		/* Code block wrapper */
		.code-wrapper {
			position: relative;
			background: var(--code-bg);
			border-radius: 8px;
			margin: 24px 0;
			border: 1px solid var(--border-color);
			overflow: hidden;
			box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
		}

		.code-header {
			display: flex;
			align-items: center;
			padding: 8px 16px;
			background: #161b22;
			border-bottom: 1px solid var(--border-color);
		}

		.lang-label {
			font-family: var(--font-mono);
			font-size: 0.7rem;
			color: var(--text-secondary);
			text-transform: uppercase;
			letter-spacing: 0.05em;
		}

		.copy-btn {
			margin-left: auto;
			background: #21262d;
			border: 1px solid var(--border-color);
			color: #c9d1d9;
			padding: 3px 8px;
			border-radius: 6px;
			font-size: 0.7rem;
			cursor: pointer;
			transition: all 0.2s;
			font-family: inherit;
			font-weight: 600;
		}

		.copy-btn:hover {
			background: #30363d;
			border-color: #8b949e;
		}

		/* Prism overrides for GitHub Dark Theme */
		pre[class*="language-"] {
			background: transparent !important;
			padding: 16px !important;
			margin: 0 !important;
			font-size: 0.85rem;
			font-family: var(--font-mono) !important;
			line-height: 1.6;
			overflow-x: auto;
			text-shadow: none !important;
			color: #c9d1d9 !important;
		}

		code[class*="language-"] {
			text-shadow: none !important;
			background: none !important;
		}

		.token.comment, .token.prolog, .token.doctype, .token.cdata { color: var(--syntax-comment) !important; }
		.token.punctuation { color: #8b949e !important; }
		.token.namespace { opacity: .7; }
		.token.property, .token.tag, .token.boolean, .token.number, .token.constant, .token.symbol, .token.deleted { color: var(--syntax-constant) !important; }
		.token.selector, .token.attr-name, .token.string, .token.char, .token.builtin, .token.inserted { color: var(--syntax-string) !important; }
		.token.operator, .token.entity, .token.url, .language-css .token.string, .style .token.string { color: var(--syntax-operator) !important; }
		.token.atrule, .token.attr-value, .token.keyword { color: var(--syntax-keyword) !important; }
		.token.function, .token.class-name { color: var(--syntax-function) !important; }
		.token.regex, .token.important, .token.variable { color: var(--syntax-attr) !important; }

		details {
			margin: 20px 0;
			border: 1px solid var(--border-color);
			border-radius: 16px;
			background: rgba(255, 255, 255, 0.02);
			transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
		}

		details[open] {
			background: rgba(255, 255, 255, 0.03);
			border-color: rgba(56, 189, 248, 0.3);
		}

		summary {
			padding: 20px 25px;
			cursor: pointer;
			font-weight: 600;
			font-size: 1.1rem;
			color: #cbd5e1;
			list-style: none;
			display: flex;
			align-items: center;
		}

		summary::before {
			content: '→';
			margin-right: 15px;
			color: #38bdf8;
			transition: transform 0.3s;
		}

		details[open] summary::before {
			transform: rotate(90deg);
		}

		.details-content {
			padding: 0 25px 25px 25px;
		}

		footer {
			text-align: center;
			padding: 80px 20px;
			color: #475569;
			font-size: 0.9rem;
		}
	</style>
</head>
<body>
	<div class="container">
		<header>
			<h1>C3 Fuzzer Dashboard</h1>`
	);

	@pool()
	{
		DateTime dt = time::datetime::now();
		html.appendf(`<p class="subtitle" id="last-run" data-timestamp="%04d-%02d-%02dT%02d:%02d:%02dZ">Last analysis run: ...</p>`,
			(int)dt.year, (int)dt.month.ordinal + 1, (int)dt.day, (int)dt.hour, (int)dt.min, (int)dt.sec);
	};

	html.appendf(
		`			<div class="stats">
				<div class="badge crash %s">
					<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
					%s
				</div>
				<div class="badge segfault %s">
					<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
					%s
				</div>
				<div class="badge segfault %s" style="color: #ff7b72; border-color: rgba(255, 123, 114, 0.2); background: rgba(255, 123, 114, 0.1);">
					<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
					%s
				</div>
			</div>
		</header>

		<div id="repro-findings">
			%s`,
		crash_count == 0 ? "zero" : "",
		crash_count == 0 ? "No crashes" : string::tformat("%d crashes", crash_count),
		segfault_count == 0 ? "zero" : "",
		segfault_count == 0 ? "No segfaults" : string::tformat("%d segfaults", segfault_count),
		timeout_count == 0 ? "zero" : "",
		timeout_count == 0 ? "No timeouts" : string::tformat("%d timeouts", timeout_count),
		findings.len() == 0 ? `<div style="background: rgba(46, 160, 67, 0.05); border: 1px solid rgba(46, 160, 67, 0.2); padding: 40px; border-radius: 12px; text-align: center; margin-top: 20px;">
				<div style="font-size: 3rem; margin-bottom: 20px;">🌟</div>
				<h3 style="color: #3fb950; margin: 0; font-size: 1.5rem;">All Systems Go</h3>
				<p style="color: var(--text-secondary); margin-top: 10px;">The fuzzer is currently running but hasn't found any reproducible crashes yet. Great job!</p>
			</div>` : ""
	);

	String current_type = "";
	foreach (f : findings)
	{
		if (f.type != current_type)
		{
			current_type = f.type;
			if (current_type == "CRASH")
			{
				html.append("<h2 id='crashes'>🔥 Compiler Crashes (Panics)</h2>");
			}
			else if (current_type == "SEGFAULT")
			{
				html.append("<h2 id='segfaults--aborts'>💀 Segfaults & Aborts</h2>");
			}
			else if (current_type == "TIMEOUT")
			{
				html.append("<h2 id='timeouts'>⏳ Timeouts</h2>");
			}
		}

		html.append("<details style='margin-bottom: 1rem;'>");

		// Extract function and source location hints from compiler output
		String func_hint = "";
		String loc_hint = "";
		if (f.output.len > 0)
		{
			if (try fidx = f.output.index_of("- Function: "))
			{
				String after = f.output[fidx + 12..];
				usz end = after.index_of("\n") ?? after.len;
				func_hint = after[:end].trim();
			}
			if (try sidx = f.output.index_of("- Source file: "))
			{
				String after = f.output[sidx + 15..];
				usz end = after.index_of("\n") ?? after.len;
				String full_path = after[:end].trim();
				if (try idx = full_path.index_of("src/compiler"))
				{
					loc_hint = full_path[idx + 4..]; // "compiler/lexer.c:279"
				}
				else if (try slash = full_path.rindex_of("/"))
				{
					loc_hint = full_path[slash + 1..];
				}
				else
				{
					loc_hint = full_path;
				}
			}
		}

		html.append("<summary style='font-family: var(--font-mono); font-size: 0.9rem;'>");
		html.append("<div style='display: flex; flex-direction: column; gap: 3px;'>");
		html.appendf("<span>%s</span>", escape_html(f.filename));
		if (loc_hint.len > 0)
		{
			html.appendf("<span style='font-size: 0.75rem; color: #8b949e; font-weight: 400;'>%s</span>", escape_html(loc_hint));
		}
		if (func_hint.len > 0)
		{
			html.appendf("<span style='font-size: 0.75rem; color: #d2a8ff; font-weight: 400;'>%s</span>", escape_html(func_hint));
		}
		html.append("</div></summary>");
		html.append("<div class='details-content'>");

		// Always show the repro command (works regardless of binary content)
		String folder_lc = f.type.to_lower_copy(tmem);
		String repro_cmd = string::tformat("cat %s/%s | c3c compile-only - --build-dir /tmp --obj-out /tmp -O0 -g0 --threads 1 --use-stdlib=no --no-entry", folder_lc, f.filename);
		html.append("<div class='code-wrapper'>");
		html.append("<div class='code-header'><span class='lang-label' style='color: #79c0ff;'>REPRO COMMAND</span>");
		html.append("<button class='copy-btn' onclick='copyCode(this)'>Copy</button></div>");
		html.appendf("<pre class='language-bash'><code class='language-bash'>%s</code></pre></div>", escape_html(repro_cmd));

		// GitHub links
		String github_blob = string::tformat("https://github.com/ManuLinares/c3fuzz/blob/master/%s/%s", folder_lc, f.filename);
		String github_raw  = string::tformat("https://raw.githubusercontent.com/ManuLinares/c3fuzz/refs/heads/master/%s/%s", folder_lc, f.filename);
		html.append("<div style='margin: 8px 0 16px 0; font-size: 0.82rem; display: flex; gap: 16px; align-items: center;'>");
		html.appendf("<a href='%s' target='_blank' style='color: #58a6ff; text-decoration: underline;'>📄 View on GitHub</a>", github_blob);
		html.appendf("<a href='%s' target='_blank' style='color: #8b949e; text-decoration: underline;'>⬇ Raw</a>", github_raw);
		html.append("</div>");

		// Show source only if it's clean text; otherwise warn about binary content
		if (!source_is_text(f.code))
		{
			html.append("<div style='background: rgba(255, 166, 77, 0.1); border: 1px solid rgba(255, 166, 77, 0.3); border-radius: 8px; padding: 12px 16px; margin: 12px 0; font-size: 0.85rem; color: #ffa64d;'>");
			html.append("⚠️ <strong>Binary content:</strong> This crash file contains non-printable bytes that can't be copy-pasted. Use the repro command above to reproduce.");
			html.append("</div>");
		}
		else
		{
			html.append("<div class='code-wrapper'>");
			html.append("<div class='code-header'><span class='lang-label'>C3 SOURCE</span>");
			html.append("<button class='copy-btn' onclick='copyCode(this)'>Copy</button></div>");
			html.appendf("<pre class='language-c3'><code class='language-c3'>%s</code></pre></div>", escape_html(f.code));
		}

		if (f.output.len > 0)
		{
			String out = f.output;
			if (try bidx = out.index_of("🙏 Please consider taking the time"))
				{
				out = out[:bidx].trim();
			}
			out = out.trim();

			html.append("<details style='border: none; background: none; margin-top: 1rem;'>");
			html.append("<summary style='font-size: 0.8rem; color: #8b949e; padding: 5px 0;'>SHOW COMPILER OUTPUT</summary>");
			html.append("<div class='code-wrapper' style='margin-top: 0.5rem;'>");
			html.append("<div class='code-header'><span class='lang-label' style='color: #ff7b72;'>COMPILER DIAGNOSTICS</span>");
			html.append("<button class='copy-btn' onclick='copyCode(this)'>Copy</button></div>");
			html.appendf("<pre class='language-text' style='color: #8b949e;'><code class='language-text'>%s</code></pre></div>", escape_html(out.trim()));

			if (try sidx = out.index_of("Source file: "))
			{
				String after = out[sidx + 13..];
				usz eidx = after.index_of("\n") ?? after.len;
				String path_and_line = after[:eidx].trim();
				if (try src_idx = path_and_line.index_of("src/compiler"))
				{
					String relative_path = path_and_line[src_idx..];
					String github_path = relative_path;
					String line_num = "";
					if (try lidx = relative_path.rindex_of(":"))
					{
						github_path = relative_path[:lidx];
						line_num = relative_path[lidx + 1..];
					}

					html.appendf(
						"<div style='margin-top: 0.5rem; font-size: 0.85rem;'>[Link] <a href='https://github.com/c3lang/c3c/blob/master/%s%s' target='_blank' style='color: #58a6ff; text-decoration: underline;'>View on GitHub: %s</a></div>",
						github_path,
						line_num.len > 0 ? string::tformat("#L%s", line_num) : "",
						path_and_line
					);
				}
			}
			html.append("</details>");
		}

		html.append("</div></details>");
	}

	html.append(
		`
		</div>
		<footer>
			A purpose-built fuzzer in C3 - <a href="https://github.com/ManuLinares/c3fuzz" style="color:#38bdf8">View Repository</a>
		</footer>
	</div>

	<script>
		// Custom C3 Language Definition for Prism
		Prism.languages.c3 = Prism.languages.extend('clike', {
			'keyword': /\b(?:module|import|fn|macro|struct|union|enum|interface|alias|typedef|faultdef|attrdef|bitstruct|const|inline|static|public|private|local|extern|var|distinct|any|void|char|bool|u8|u16|u32|u64|u128|i8|i16|i32|i64|i128|f32|f64|f128|iptr|uptr|isz|usz|return|if|else|while|do|for|switch|case|default|break|continue|next|goto|defer|try|catch|throw|assert|include|echo|exec)\b/,
			'operator': /[<>]=?|[!=]=?|&&|\|\||[+*\-%/&|^~]=?|->|\.\.\.|\.?\?/,
			'annotation': {
				pattern: /@\w+/,
				alias: 'attr'
			}
		});

		window.copyCode = (btn) => {
			const container = btn.closest(".code-wrapper");
			const code = container.querySelector("code").textContent;
			navigator.clipboard.writeText(code);
			const originalText = btn.innerText;
			btn.innerText = "Copied!";
			btn.style.color = "#34d399";
			setTimeout(() => {
				btn.innerText = originalText;
				btn.style.color = "";
			}, 2000);
		};

		document.addEventListener("DOMContentLoaded", () => {
			Prism.highlightAll();

			// Update "Last Run" periodically
			const timeEl = document.getElementById('last-run');
			const timestamp = new Date(timeEl.dataset.timestamp);

			function updateTime() {
				const diff = Math.floor((new Date() - timestamp) / 1000);
				if (diff < 60) timeEl.innerText = "Last analysis run: " + diff + "s ago";
				else if (diff < 3600) timeEl.innerText = "Last analysis run: " + Math.floor(diff / 60) + "m ago";
				else if (diff < 86400) timeEl.innerText = "Last analysis run: " + Math.floor(diff / 3600) + "h ago";
				else timeEl.innerText = "Last analysis run: " + Math.floor(diff / 86400) + "d ago";
			}

			updateTime();
			setInterval(updateTime, 10000);
		});
	</script>
</body>
</html>`
	);

	if (catch std::io::file::save("fuzzer_report.html", html.str_view()))
	{
		log::error("❌ Failed to save dashboard!");
	}
	else
	{
		log::info("✅ Generated Dashboard: fuzzer_report.html");
	}
}
