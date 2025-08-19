#!/usr/bin/env python3
import os
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
from urllib.parse import urlparse

# ------------------------- HELPERS -------------------------

def run_command_live(cmd, tool_tag, logger):
    logger(f"\n--- {tool_tag} START ---\n")
    process = subprocess.Popen(cmd, shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               text=True)
    for line in process.stdout:
        logger(f"[{tool_tag}] {line}")
    process.wait()
    logger(f"--- {tool_tag} END ---\n")

def run_phase(cmds, phase_name, logger):
    logger(f"\n[=] Starting {phase_name}...\n")
    threads = []
    for cmd, tag in cmds:
        t = threading.Thread(target=run_command_live, args=(cmd, tag, logger))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    logger(f"[=] {phase_name} finished.\n")

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path

def domain_dir_from_url(url_fallback, default_dir="recon_misc"):
    """
    Try to derive recon_<domain> from URL string. If not a URL, fall back.
    """
    parsed = urlparse(url_fallback if "://" in url_fallback else f"http://{url_fallback}")
    host = (parsed.netloc or parsed.path).strip()
    if not host:
        host = "target"
    return f"recon_{host}"

def list_from_textbox(textbox):
    lines = [x.strip() for x in textbox.get("1.0", tk.END).splitlines()]
    return [x for x in lines if x]

def logger_enum(msg):
    output_enum.insert(tk.END, msg)
    output_enum.see(tk.END)
    output_enum.update_idletasks()

def logger_live(msg):
    output_live.insert(tk.END, msg)
    output_live.see(tk.END)
    output_live.update_idletasks()

def logger_dirb(msg):
    output_dirb.insert(tk.END, msg)
    output_dirb.see(tk.END)
    output_dirb.update_idletasks()

def flags_from_box(box):
    # one flag per line
    raw = [l.strip() for l in box.get("1.0", tk.END).splitlines()]
    return [l for l in raw if l]

# ------------------------- TAB 1: ENUMERATION -------------------------

def run_enum():
    domain = entry_domain.get("1.0", tk.END).strip().splitlines()[0]
    wordlist = var_wordlist.get().strip()
    github_token = entry_github.get().strip()
    chaos_key = entry_chaos.get().strip()
    inscope = list_from_textbox(txt_inscope)  # can contain * wildcards (we just substring match)
    outscope = list_from_textbox(txt_outscope)

    if not domain or not wordlist:
        messagebox.showerror("Error", "Please fill in Domain and Wordlist at least!")
        return

    base_dir = ensure_dir(f"recon_{domain}")
    out_dir = ensure_dir(os.path.join(base_dir, "subdomains"))

    logger_enum(f"[+] Starting recon for {domain}\n")
    logger_enum(f"[i] Output folder: {out_dir}\n")

    # Passive
    passive_cmds = [
        (f"sublist3r -d {domain} -t 50 -o {out_dir}/sublist3r.txt", "Sublist3r"),
        (f"assetfinder --subs-only {domain} | tee {out_dir}/assetfinder.txt", "Assetfinder"),
        (f"subfinder -d {domain} -silent -o {out_dir}/subfinder.txt", "Subfinder"),
        (f"findomain -t {domain} -o {out_dir}/findomain.txt", "Findomain"),
    ]
    if github_token:
        passive_cmds.append(
            (f"python3 github-subdomains.py -t {github_token} -d {domain} > {out_dir}/github_subs.txt", "Github")
        )
    if chaos_key:
        passive_cmds.append(
            (f"chaos -d {domain} -key {chaos_key} -o {out_dir}/chaos.txt", "Chaos")
        )

    # Active
    resolvers = os.path.expanduser("~/resolvers.txt")
    active_cmds = [
        (f"puredns bruteforce {wordlist} {domain} --resolvers {resolvers} --write {out_dir}/puredns.txt", "PureDNS"),
        (f"dnsx -d {domain} -w {wordlist} -r {resolvers} -o {out_dir}/dnsx.txt", "DNSx"),
    ]

    if var_enum_parallel.get():
        (passive_cmds, "Passive Enumeration", logger_enum)
    else:
        for cmd, tag in passive_cmds:
            run_command_live(cmd, tag, logger_enum)

    if var_enum_parallel.get():
        run_phase(active_cmds, "Active Enumeration", logger_enum)
    else:
    	for cmd, tag in active_cmds:
            run_command_live(cmd, tag, logger_enum)

    # Merge + clean
    raw_file = os.path.join(out_dir, "all_subdomains_raw.txt")
    run_command_live(f"cat {out_dir}/*.txt | sort -u > {raw_file}", "Merger", logger_enum)

    clean_file = os.path.join(out_dir, "clean_subdomains.txt")
    run_command_live(
        f"grep -E '^[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}$' {raw_file} | sort -u > {clean_file}",
        "Cleaner",
        logger_enum
    )

    # Scope filter (substring match, wildcards treated as plain *)
    if inscope or outscope:
        with open(clean_file, "r") as f:
            subs = [s.strip() for s in f if s.strip()]
        def match_any(needles, s):
            for n in needles:
                if n and n.replace("*", "") in s:
                    return True
            return False
        filtered = [s for s in subs if (not inscope or match_any(inscope, s)) and not match_any(outscope, s)]
        with open(clean_file, "w") as f:
            f.write("\n".join(sorted(set(filtered))) + ("\n" if filtered else ""))

    logger_enum(f"\n[+] Done! File saved: {clean_file}\n")

def start_enum_thread():
    threading.Thread(target=run_enum, daemon=True).start()

# ------------------------- TAB 2: LIVE/DEAD + STATUS SPLITS -------------------------

HTTP_2XX = "200,201,202,203,204,206"
HTTP_3XX = "300,301,302,303,304,307,308"
HTTP_4XX = "400,401,402,403,404,405,409,410,429"
HTTP_5XX = "500,501,502,503,504,505"

def run_livecheck():
    filepath = var_subs_file.get().strip()
    if not filepath:
        messagebox.showerror("Error", "Please select a subdomain file!")
        return

    base_dir = os.path.dirname(filepath) or "."
    # Copy/alias "all_urls.txt" to be the given list (raw input)
    all_urls = os.path.join(base_dir, "all_urls.txt")
    try:
        with open(filepath, "r") as fin, open(all_urls, "w") as fout:
            for line in fin:
                if line.strip():
                    fout.write(line.strip() + "\n")
    except Exception as e:
        logger_live(f"[!] Failed to write all_urls.txt: {e}\n")

    live_file = os.path.join(base_dir, "live.txt")
    dead_file = os.path.join(base_dir, "dead.txt")

    logger_live(f"[+] Checking live/dead for: {filepath}\n")

    # Live list via httpx
    run_command_live(f"httpx -l {filepath} -silent -o {live_file}", "httpx-live", logger_live)

    # Make dead.txt = all - live
    try:
        all_set = set(x.strip() for x in open(filepath) if x.strip())
        live_set = set(x.strip() for x in open(live_file) if x.strip())
        dead = sorted(all_set - live_set)
        with open(dead_file, "w") as f:
            f.write("\n".join(dead) + ("\n" if dead else ""))
    except Exception as e:
        logger_live(f"[!] Dead list build failed: {e}\n")

    # Status splits
    p200 = os.path.join(base_dir, "200.txt")
    p300 = os.path.join(base_dir, "300.txt")
    p400 = os.path.join(base_dir, "400.txt")
    p500 = os.path.join(base_dir, "500.txt")

    cmds = [
        (f"httpx -l {filepath} -silent -mc {HTTP_2XX} -o {p200}", "httpx-200s"),
        (f"httpx -l {filepath} -silent -mc {HTTP_3XX} -o {p300}", "httpx-300s"),
        (f"httpx -l {filepath} -silent -mc {HTTP_4XX} -o {p400}", "httpx-400s"),
        (f"httpx -l {filepath} -silent -mc {HTTP_5XX} -o {p500}", "httpx-500s"),
    ]
    run_phase(cmds, "HTTP Status Split", logger_live)

    logger_live(f"[+] Saved:\n  {all_urls}\n  {live_file}\n  {dead_file}\n  {p200}\n  {p300}\n  {p400}\n  {p500}\n")

def start_live_thread():
    threading.Thread(target=run_livecheck, daemon=True).start()

# ------------------------- TAB 3: DIRECTORY / FILE BRUTEFORCE -------------------------

def run_dirb():
    target = entry_target_url.get("1.0", tk.END).strip().splitlines()[0]
    wordlist = var_dir_wordlist.get().strip()

    if not target or not wordlist:
        messagebox.showerror("Error", "Please fill in Target URL and Wordlist!")
        return

    # Base folder from target host
    base_dir = ensure_dir(domain_dir_from_url(target))
    out_dir = ensure_dir(os.path.join(base_dir, "dirbusting"))
    logger_dirb(f"[+] Target: {target}\n[i] Output folder: {out_dir}\n")

    # Selected tools
    selected = []
    if var_ffuf.get():      selected.append("ffuf")
    if var_gobuster.get():  selected.append("gobuster")
    if var_dirsearch.get(): selected.append("dirsearch")
    if var_wfuzz.get():     selected.append("wfuzz")
    if var_nikto.get():     selected.append("nikto")

    if not selected:
        messagebox.showerror("Error", "Select at least one tool.")
        return

    flags = flags_from_box(txt_flags)  # one per line
    # Join flags safely
    extra = " ".join(flags) if flags else ""

    # Per-tool output files
    tool_out = {
        "ffuf":      os.path.join(out_dir, "ffuf.txt"),
        "gobuster":  os.path.join(out_dir, "gobuster.txt"),
        "dirsearch": os.path.join(out_dir, "dirsearch.txt"),
        "wfuzz":     os.path.join(out_dir, "wfuzz.txt"),
        "nikto":     os.path.join(out_dir, "nikto.txt"),
    }

    cmds = []
    # NOTE: We keep commands simple. You can adjust via the flags box.
    if "ffuf" in selected:
        cmds.append((f'ffuf -u "{target.rstrip("/")}/FUZZ" -w "{wordlist}" {extra} | tee "{tool_out["ffuf"]}"', "ffuf"))
    if "gobuster" in selected:
        cmds.append((f'gobuster dir -u "{target}" -w "{wordlist}" {extra} | tee "{tool_out["gobuster"]}"', "gobuster"))
    if "dirsearch" in selected:
        cmds.append((f'python3 -m dirsearch -u "{target}" -w "{wordlist}" {extra} | tee "{tool_out["dirsearch"]}"', "dirsearch"))
    if "wfuzz" in selected:
        cmds.append((f'wfuzz -z file,"{wordlist}" -u "{target.rstrip("/")}/FUZZ" {extra} | tee "{tool_out["wfuzz"]}"', "wfuzz"))
    if "nikto" in selected:
        cmds.append((f'nikto -host "{target}" {extra} | tee "{tool_out["nikto"]}"', "nikto"))

    # Run one or many in threads
    if len(cmds) == 1:
        run_command_live(cmds[0][0], cmds[0][1], logger_dirb)
    else:
        run_phase(cmds, "Dir/File Bruteforce (parallel)", logger_dirb)

    # Build candidate URLs from wordlist and check with httpx to produce combined + splits
    candidates = os.path.join(out_dir, "candidates.txt")
    try:
        with open(wordlist, "r") as f_in, open(candidates, "w") as f_out:
            base = target.rstrip("/")
            for line in f_in:
                p = line.strip().lstrip("/")
                if p:
                    f_out.write(f"{base}/{p}\n")
        logger_dirb(f"[i] Built candidate list: {candidates}\n")
    except Exception as e:
        logger_dirb(f"[!] Failed to build candidates: {e}\n")
        return

    all_dirs = os.path.join(out_dir, "all_dirs.txt")
    # Save all positives to all_dirs.txt
    run_command_live(f"httpx -l {candidates} -silent -o {all_dirs}", "httpx-all_dirs", logger_dirb)

    logger_dirb(f"[+] Saved dirbusting results in {out_dir}\n"
                f"    - Tool files: {', '.join([os.path.basename(tool_out[t]) for t in selected])}\n"
                f"    - Combined:   {all_dirs}\n")

def start_dirb_thread():
    threading.Thread(target=run_dirb, daemon=True).start()

# ------------------------- GUI -------------------------

root = tk.Tk()
root.title("ReconBud")
root.configure(bg="black")

style = ttk.Style()
try:
    style.theme_use("clam")
except:
    pass

canvas = tk.Canvas(root, bg="black")
scroll_y = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
notebook = ttk.Notebook(canvas)

notebook_frame = tk.Frame(canvas, bg="black")
notebook.pack(fill="both", expand=True)

canvas.create_window((0,0), window=notebook_frame, anchor="nw")
canvas.update_idletasks()
canvas.configure(scrollregion=canvas.bbox("all"), yscrollcommand=scroll_y.set)

canvas.pack(fill="both", expand=True, side="left")
scroll_y.pack(fill="y", side="right")

# ===== TAB 1: ENUMERATION =====
tab1 = tk.Frame(notebook, bg="black")
notebook.add(tab1, text="Subdomain Enumeration")

var_wordlist = tk.StringVar()

tk.Label(tab1, text="Target Domain:", fg="green", bg="black").grid(row=0, column=0, sticky="w")
entry_domain = scrolledtext.ScrolledText(tab1, height=4, bg="black", fg="green", insertbackground="green")
entry_domain.grid(row=0, column=1, columnspan=2, sticky="we")

tk.Label(tab1, text="Wordlist:", fg="green", bg="black").grid(row=1, column=0, sticky="w")
tk.Entry(tab1, textvariable=var_wordlist, bg="black", fg="green", insertbackground="green").grid(row=1, column=1, sticky="we")
tk.Button(tab1, text="Browse", command=lambda: var_wordlist.set(filedialog.askopenfilename()), bg="green", fg="black").grid(row=1, column=2)

tk.Label(tab1, text="GitHub Token (optional):", fg="green", bg="black").grid(row=2, column=0, sticky="w")
entry_github = tk.Entry(tab1, bg="black", fg="green", insertbackground="green")
entry_github.grid(row=2, column=1, sticky="we")

tk.Label(tab1, text="Chaos API Key (optional):", fg="green", bg="black").grid(row=3, column=0, sticky="w")
entry_chaos = tk.Entry(tab1, bg="black", fg="green", insertbackground="green")
entry_chaos.grid(row=3, column=1, sticky="we")

tk.Label(tab1, text="In-scope (one per line, * allowed):", fg="green", bg="black").grid(row=4, column=0, sticky="w")
txt_inscope = scrolledtext.ScrolledText(tab1, height=8, bg="black", fg="green", insertbackground="green")
txt_inscope.grid(row=4, column=1, columnspan=2, sticky="we")

tk.Label(tab1, text="Out-of-scope (one per line, * allowed):", fg="green", bg="black").grid(row=5, column=0, sticky="w")
txt_outscope = scrolledtext.ScrolledText(tab1, height=8, bg="black", fg="green", insertbackground="green")
txt_outscope.grid(row=5, column=1, columnspan=2, sticky="we")

var_enum_parallel = tk.BooleanVar(value=True)
tk.Checkbutton(tab1, text="Run in Parallel", variable=var_enum_parallel,
               bg="black", fg="green", selectcolor="black").grid(row=6, column=0, sticky="w")


tk.Button(tab1, text="Start Enumeration", command=start_enum_thread, bg="green", fg="black").grid(row=6, column=0, columnspan=3, pady=10)

output_enum = scrolledtext.ScrolledText(tab1, height=15, bg="black", fg="green", insertbackground="green")
output_enum.grid(row=7, column=0, columnspan=3, sticky="nsew")

tab1.grid_columnconfigure(1, weight=1)

# ===== TAB 2: LIVE/DEAD CHECKER =====
tab2 = tk.Frame(notebook, bg="black")
notebook.add(tab2, text="Live/Dead Checker")

var_subs_file = tk.StringVar()

tk.Label(tab2, text="Subdomain File:", fg="green", bg="black").grid(row=0, column=0, sticky="w")
tk.Entry(tab2, textvariable=var_subs_file, bg="black", fg="green", insertbackground="green").grid(row=0, column=1, sticky="we")
tk.Button(tab2, text="Browse", command=lambda: var_subs_file.set(filedialog.askopenfilename()), bg="green", fg="black").grid(row=0, column=2)

tk.Button(tab2, text="Run Live/Dead + Splits", command=start_live_thread, bg="green", fg="black").grid(row=1, column=0, columnspan=3, pady=10)

output_live = scrolledtext.ScrolledText(tab2, height=18, bg="black", fg="green", insertbackground="green")
output_live.grid(row=2, column=0, columnspan=3, sticky="nsew")
tab2.grid_columnconfigure(1, weight=1)

# ===== TAB 3: DIR/FILE BRUTEFORCE =====
tab3 = tk.Frame(notebook, bg="black")
notebook.add(tab3, text="Dir/File Bruteforce")

var_dir_wordlist = tk.StringVar()
var_ffuf = tk.BooleanVar(value=True)
var_gobuster = tk.BooleanVar(value=False)
var_dirsearch = tk.BooleanVar(value=True)
var_wfuzz = tk.BooleanVar(value=False)
var_nikto = tk.BooleanVar(value=False)

tk.Label(tab3, text="Target URL/Domain:", fg="green", bg="black").grid(row=0, column=0, sticky="w")
entry_target_url = scrolledtext.ScrolledText(tab3, height=4, bg="black", fg="green", insertbackground="green")
entry_target_url.grid(row=0, column=1, columnspan=2, sticky="we")

tk.Label(tab3, text="Wordlist:", fg="green", bg="black").grid(row=1, column=0, sticky="w")
tk.Entry(tab3, textvariable=var_dir_wordlist, bg="black", fg="green", insertbackground="green").grid(row=1, column=1, sticky="we")
tk.Button(tab3, text="Browse", command=lambda: var_dir_wordlist.set(filedialog.askopenfilename()), bg="green", fg="black").grid(row=1, column=2)

tk.Label(tab3, text="Tools:", fg="green", bg="black").grid(row=2, column=0, sticky="w")
tools_frame = tk.Frame(tab3, bg="black")
tools_frame.grid(row=2, column=1, columnspan=2, sticky="w")
tk.Checkbutton(tools_frame, text="ffuf", variable=var_ffuf, bg="black", fg="green", selectcolor="black").grid(row=0, column=0, sticky="w")
tk.Checkbutton(tools_frame, text="gobuster", variable=var_gobuster, bg="black", fg="green", selectcolor="black").grid(row=0, column=1, sticky="w")
tk.Checkbutton(tools_frame, text="dirsearch", variable=var_dirsearch, bg="black", fg="green", selectcolor="black").grid(row=0, column=2, sticky="w")
tk.Checkbutton(tools_frame, text="wfuzz", variable=var_wfuzz, bg="black", fg="green", selectcolor="black").grid(row=0, column=3, sticky="w")
tk.Checkbutton(tools_frame, text="nikto", variable=var_nikto, bg="black", fg="green", selectcolor="black").grid(row=0, column=4, sticky="w")

tk.Label(tab3, text="Custom Flags (one per line):", fg="green", bg="black").grid(row=3, column=0, sticky="w")
txt_flags = scrolledtext.ScrolledText(tab3, height=6, bg="black", fg="green", insertbackground="green")
txt_flags.grid(row=3, column=1, columnspan=2, sticky="we")

tk.Button(tab3, text="Run Dir Bruteforce", command=start_dirb_thread, bg="green", fg="black").grid(row=4, column=0, columnspan=3, pady=10)

output_dirb = scrolledtext.ScrolledText(tab3, height=18, bg="black", fg="green", insertbackground="green")
output_dirb.grid(row=5, column=0, columnspan=3, sticky="nsew")

tab3.grid_columnconfigure(1, weight=1)

# ------------------------- MAINLOOP -------------------------
root.mainloop()
