"""User interface in the style of Windows 95/98: grey, square, system font."""
from __future__ import annotations

import os
import platform
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import ioc, log, quarantine, report, scanner
from .core import count, APPNAME, DATA_DIR, HIT, INFO, OK, SKIP, VERSION, WARN, Context, ensure_dir, is_admin, os_name

GRAY, NAVY, WHITE = "#C0C0C0", "#000080", "#FFFFFF"
SEV_COLORS = {HIT: "#C00000", WARN: "#7F5F00", SKIP: "#404040", INFO: "#000080", OK: "#006000"}
SEV_RANK = {HIT: 0, WARN: 1, SKIP: 2, INFO: 3, OK: 4}


def _pick(fams, wanted):
    low = {f.lower(): f for f in fams}
    for w in wanted:
        if w.lower() in low:
            return low[w.lower()]
    return wanted[-1]


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.ctx = None
        self.worker = None
        self.items = {}
        fams = tkfont.families()
        self.f_ui = (_pick(fams, ["MS Sans Serif", "Microsoft Sans Serif", "Tahoma", "Liberation Sans", "DejaVu Sans", "Arial"]), 9)
        self.f_bold = (self.f_ui[0], 9, "bold")
        self.f_mono = (_pick(fams, ["Fixedsys", "Courier New", "Liberation Mono", "DejaVu Sans Mono", "Courier"]), 9)
        root.title(f"{APPNAME} {VERSION} – beta")
        root.configure(bg=GRAY)
        root.geometry("980x770")
        root.minsize(760, 620)
        root.option_add("*Font", self.f_ui)
        root.option_add("*Background", GRAY)
        self._style()
        self._build()
        self._refresh_info()
        root.after(120, self._poll)
        root.after(200, self._consent)

    # ------------------------------------------------------------- layout
    def _style(self):
        st = ttk.Style(self.root)
        st.theme_use("classic" if "classic" in st.theme_names() else st.theme_use())
        st.configure("Treeview", background=WHITE, fieldbackground=WHITE, foreground="#000", font=self.f_ui, rowheight=19,
                     borderwidth=2, relief="sunken")
        st.configure("Treeview.Heading", background=GRAY, font=self.f_bold, relief="raised", borderwidth=2)
        st.map("Treeview", background=[("selected", NAVY)], foreground=[("selected", WHITE)])
        st.configure("Horizontal.TProgressbar", background=NAVY, troughcolor=WHITE, borderwidth=2, relief="sunken", thickness=16)
        st.configure("Vertical.TScrollbar", background=GRAY, troughcolor="#DFDFDF", borderwidth=2, relief="raised", arrowcolor="#000")

    def _btn(self, parent, text, cmd, w=17, h=3, bold=True):
        return tk.Button(parent, text=text, command=cmd, width=w, height=h, relief="raised", bd=3, bg=GRAY,
                         activebackground="#D4D0C8", font=self.f_bold if bold else self.f_ui, highlightthickness=0,
                         cursor="hand2", padx=2, pady=2)

    def _build(self):
        r = self.root
        bar = tk.Frame(r, bg=NAVY)
        bar.pack(fill="x", padx=3, pady=(3, 0))
        logo = tk.Label(bar, text=">_SCS", bg="#000000", fg="#00FF00", font=(self.f_mono[0], 12, "bold"), padx=8, pady=2)
        logo.pack(side="left", padx=(2, 8), pady=2)
        tk.Label(bar, text=f"{APPNAME} {VERSION} · Sedic Code Studio", bg=NAVY, fg=WHITE, font=(self.f_ui[0], 10, "bold")).pack(side="left")
        tk.Label(bar, text="BETA", bg=NAVY, fg="#FFFF00", font=self.f_bold).pack(side="right", padx=8)

        self.info = tk.Label(r, text="", anchor="w", justify="left", relief="sunken", bd=2, bg=GRAY, padx=6, pady=3)
        self.info.pack(fill="x", padx=6, pady=(6, 4))

        tiles = tk.Frame(r, bg=GRAY, relief="groove", bd=2)
        tiles.pack(fill="x", padx=6, pady=2)
        defs = [
            ("Quick scan\nThis computer", lambda: self.start("quick")),
            ("Full scan\nThis computer", lambda: self.start("full")),
            ("Android\nover USB", lambda: self.start("android")),
            ("iPhone\nfrom backup", lambda: self.start("ios")),
            ("iPhone\nJailbreak/SSH", lambda: self.start("ios_ssh")),
            ("Update\nindicators", self.update_ioc),
            ("Show\nquarantine", self.show_quarantine),
            ("Self-test\n(harmless)", lambda: self.start("selftest")),
            ("Network watch\nlive check", lambda: self.start("netwatch")),
            ("Privacy\ncleanup", self.show_cleanup),
            ("Combine\nreports", self.combine_reports),
            ("About\nSCS Scanner", self.show_about),
        ]
        for i, (t, c) in enumerate(defs):
            self._btn(tiles, t, c).grid(row=i // 4, column=i % 4, padx=4, pady=4, sticky="nsew")
        for c in range(4):
            tiles.grid_columnconfigure(c, weight=1)

        opt = tk.Frame(r, bg=GRAY)
        opt.pack(fill="x", padx=6, pady=2)
        self.v_root = tk.BooleanVar(value=False)
        tk.Checkbutton(opt, text="Root mode (Android “su”, iPhone SSH, rooted devices)", variable=self.v_root, bg=GRAY,
                       activebackground=GRAY, selectcolor=WHITE).pack(side="left")
        self._btn(opt, "Cancel", self.cancel, w=11, h=1, bold=False).pack(side="right", padx=2)
        self._btn(opt, "Save report …", self.save_report, w=16, h=1, bold=False).pack(side="right", padx=2)
        if os_name() == "windows" and not is_admin():
            self._btn(opt, "Restart as administrator", self.elevate, w=24, h=1, bold=False).pack(side="right", padx=2)

        pane = tk.PanedWindow(r, orient="vertical", bg=GRAY, sashwidth=6, sashrelief="raised", bd=0)
        pane.pack(fill="both", expand=True, padx=6, pady=4)
        top = tk.Frame(pane, bg=GRAY)
        self.tree = ttk.Treeview(top, columns=("s", "a", "t"), show="headings", selectmode="browse")
        for col, txt, w in (("s", "Status", 110), ("a", "Area", 150), ("t", "Finding", 640)):
            self.tree.heading(col, text=txt, command=lambda c=col: self._sort(c))
            self.tree.column(col, width=w, anchor="w", stretch=(col == "t"))
        for sev, colr in SEV_COLORS.items():
            self.tree.tag_configure(sev, foreground=colr)
        sb = ttk.Scrollbar(top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._select)
        pane.add(top, minsize=150, height=300)

        bot = tk.Frame(pane, bg=GRAY)
        acts = tk.Frame(bot, bg=GRAY)
        acts.pack(fill="x", pady=(0, 3))
        self.b_quar = self._btn(acts, "Move to quarantine", self.act_quarantine, w=20, h=1, bold=False)
        self.b_uninst = self._btn(acts, "Remove app from phone", self.act_uninstall, w=22, h=1, bold=False)
        self.b_open = self._btn(acts, "Open folder", self.act_open, w=14, h=1, bold=False)
        self.b_copy = self._btn(acts, "Copy text", self.act_copy, w=12, h=1, bold=False)
        for b in (self.b_quar, self.b_uninst, self.b_open, self.b_copy):
            b.pack(side="left", padx=2)
        self.detail = tk.Text(bot, height=9, wrap="word", font=self.f_mono, bg=WHITE, relief="sunken", bd=2)
        self.detail.pack(fill="both", expand=True)
        pane.add(bot, minsize=110)

        sbar = tk.Frame(r, bg=GRAY)
        sbar.pack(fill="x", padx=6, pady=(0, 6), side="bottom", before=pane)
        self.status = tk.Label(sbar, text="Ready.", anchor="w", relief="sunken", bd=2, bg=GRAY, padx=4)
        self.status.pack(side="left", fill="x", expand=True)
        self.counts = tk.Label(sbar, text="", anchor="e", relief="sunken", bd=2, bg=GRAY, padx=6, width=34)
        self.counts.pack(side="left", padx=(4, 0))
        self.prog = ttk.Progressbar(sbar, length=180, mode="determinate", style="Horizontal.TProgressbar")
        self.prog.pack(side="left", padx=(4, 0))
        self._set_actions(None)

    # ------------------------------------------------------------- helpers
    def _refresh_info(self, vpn=None):
        meta = ioc.load_meta()
        n = len(meta.get("feeds", []))
        idx = f"{count(n, 'indicator source')}, updated {meta.get('updated')}" if n else "No indicators – please click “Update indicators”"
        adm = "administrator/root" if is_admin() else "limited rights"
        vpn_txt = f"    VPN: {vpn}" if vpn else ""
        self.info.config(text=f"System: {platform.system()} {platform.release()} · {platform.node()}    Rights: {adm}    {idx}{vpn_txt}")

    def _consent(self):
        flag = os.path.join(DATA_DIR, "consent.txt")
        if os.path.exists(flag):
            return
        ok = messagebox.askokcancel(
            "Please read",
            f"{APPNAME} {VERSION} – before the first scan:\n\n"
            "Only check your own devices, or devices whose owner has agreed. "
            "Searching other people's devices without consent is a criminal offence in many countries.\n\n"
            "Scan results stay on this computer. The program only connects to the internet when you update the "
            "indicator lists or check for a new version.\n\n"
            "A result without detections is no guarantee. The software is provided under the Apache License 2.0, "
            "without warranty.\n\nDo you agree?")
        if not ok:
            self.root.destroy()
            return
        ensure_dir(DATA_DIR)
        with open(flag, "w", encoding="utf-8") as fh:
            fh.write(f"agreed {time.strftime('%Y-%m-%d %H:%M')} version {VERSION}\n")

    def _set_status(self, text, pct=None):
        self.status.config(text=text)
        if pct is not None:
            self.prog["value"] = pct

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "finding":
                    self._add_row(payload)
                elif kind == "status":
                    self._set_status(*payload)
                elif kind == "log":
                    self.detail.insert("end", payload + "\n")
                    self.detail.see("end")
                elif kind == "done":
                    self._set_status(payload, 100)
                    self._refresh_info(self.ctx.meta.get("vpn") if self.ctx else None)
                elif kind == "error":
                    messagebox.showerror(APPNAME, payload)
        except queue.Empty:
            pass
        if self.ctx:
            c = self.ctx.counts()
            self.counts.config(text=f"Detected {c[HIT]}  ·  Warnings {c[WARN]}  ·  Info {c[INFO]}")
        self.root.after(120, self._poll)

    def _add_row(self, f):
        iid = self.tree.insert("", "end", values=(f.sev, f.area, f.title), tags=(f.sev,))
        self.items[iid] = f
        if f.sev in (HIT, WARN):
            self.tree.move(iid, "", self._insert_pos(f))

    def _insert_pos(self, f):
        rank = SEV_RANK[f.sev]
        for i, iid in enumerate(self.tree.get_children()):
            if SEV_RANK[self.items[iid].sev] > rank:
                return i
        return "end"

    def _sort(self, col):
        idx = {"s": 0, "a": 1, "t": 2}[col]
        rows = list(self.tree.get_children())
        key = (lambda i: SEV_RANK.get(self.items[i].sev, 9)) if col == "s" else (lambda i: str(self.tree.item(i)["values"][idx]).lower())
        for pos, iid in enumerate(sorted(rows, key=key)):
            self.tree.move(iid, "", pos)

    def _cur(self):
        sel = self.tree.selection()
        return self.items.get(sel[0]) if sel else None

    def _select(self, _=None):
        f = self._cur()
        self.detail.delete("1.0", "end")
        if f:
            self.detail.insert("end", f"[{f.sev}] {f.area} – {f.title}\n\n{f.detail or ''}\n")
            if f.source:
                self.detail.insert("end", f"\nIndicator source: {f.source}\n")
        self._set_actions(f)

    def _set_actions(self, f):
        a = (f.action or {}) if f else {}
        self.b_quar.config(state="normal" if a.get("type") == "quarantine" or (f and f.path and os.path.isfile(f.path)) else "disabled")
        self.b_uninst.config(state="normal" if a.get("type") == "adb_uninstall" else "disabled")
        self.b_open.config(state="normal" if a.get("type") in ("open", "quarantine") or (f and f.path) else "disabled")
        self.b_copy.config(state="normal" if f else "disabled")

    # ------------------------------------------------------------- actions
    def start(self, kind):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(APPNAME, "A check is already running.")
            return
        args = {}
        if kind == "ios":
            from .ios import default_backup_dirs
            found = default_backup_dirs()
            path = filedialog.askdirectory(title="Choose the iPhone backup folder (contains Manifest.plist)",
                                           initialdir=found[0] if found else os.path.expanduser("~"))
            if not path:
                return
            pw = simpledialog.askstring(APPNAME, "Backup password (only for encrypted backups, otherwise leave empty):", show="*")
            args = {"path": path, "password": pw or None}
        if kind == "netwatch":
            minutes = simpledialog.askinteger(APPNAME, "How many minutes should the network be watched?\n"
                                              "Use the device normally meanwhile (messengers, mail, browser).",
                                              initialvalue=10, minvalue=1, maxvalue=240)
            if not minutes:
                return
            args = {"minutes": minutes}
        if kind == "ios_ssh":
            host = simpledialog.askstring(APPNAME, "IP address of the iPhone (jailbreak with OpenSSH, key-based login):")
            if not host:
                return
            args = {"host": host.strip()}
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.items.clear()
        self.detail.delete("1.0", "end")
        self.ctx = Context(full=(kind == "full"), root_mode=self.v_root.get(),
                           log=lambda m: self.q.put(("status", (m, None))),
                           emit=lambda f: self.q.put(("finding", f)),
                           progress=lambda t, p: self.q.put(("status", (t, p))))
        ctx = self.ctx

        def job():
            try:
                if kind in ("quick", "full"):
                    scanner.system_scan(ctx)
                elif kind == "android":
                    scanner.android_scan(ctx)
                elif kind == "ios":
                    scanner.ios_backup_scan(ctx, **args)
                elif kind == "ios_ssh":
                    scanner.ios_ssh_scan(ctx, **args)
                elif kind == "selftest":
                    scanner.selftest(ctx)
                elif kind == "netwatch":
                    from . import netwatch
                    netwatch.watch(ctx, **args)
                c = ctx.counts()
                self.q.put(("done", "Cancelled." if ctx.cancel else f"Done: {c[HIT]} detected, {count(c[WARN], 'warning')}."))
            except Exception as e:  # noqa: BLE001
                path = log.crash(*sys.exc_info())
                self.q.put(("error", f"{type(e).__name__}: {e}\n\nDetails were saved to:\n{path}"))
                self.q.put(("done", "Error."))

        self.prog["value"] = 0
        self.worker = threading.Thread(target=job, daemon=True)
        self.worker.start()

    def cancel(self):
        if self.ctx:
            self.ctx.cancel = True
            self._set_status("Cancelling …")

    def update_ioc(self):
        if self.worker and self.worker.is_alive():
            return
        self.detail.delete("1.0", "end")

        def job():
            try:
                ok, fails = ioc.update(log=lambda m: self.q.put(("log", m)))
                self.q.put(("done", f"Indicators updated: {count(ok, 'source')} loaded" + (f", {count(len(fails), 'error')}" if fails else "")))
            except Exception as e:  # noqa: BLE001
                self.q.put(("error", f"Update failed: {e}\nIs there an internet connection? With a VPN or proxy, check that "
                                     "github.com is reachable."))
                self.q.put(("done", "Update failed."))
        self._set_status("Loading indicators …", 10)
        self.worker = threading.Thread(target=job, daemon=True)
        self.worker.start()

    def save_report(self):
        if not self.ctx or not self.ctx.findings:
            messagebox.showinfo(APPNAME, "There is no result yet.")
            return
        p = filedialog.asksaveasfilename(title="Save report", defaultextension=".html",
                                         filetypes=[("HTML report", "*.html"), ("JSON data", "*.json")],
                                         initialfile="SCS-Report.html")
        if not p:
            return
        (report.save_json if p.lower().endswith(".json") else report.save_html)(self.ctx, p)
        self._set_status(f"Report saved: {p}")

    def act_quarantine(self):
        f = self._cur()
        if not f:
            return
        p = (f.action or {}).get("path") or f.path
        if not p or not os.path.isfile(p):
            messagebox.showwarning(APPNAME, "There is no single file for this finding.")
            return
        if not messagebox.askyesno(APPNAME, f"Move this file to quarantine?\n\n{p}\n\nIt can be restored at any time."):
            return
        try:
            qid = quarantine.quarantine(p, f.title)
            messagebox.showinfo(APPNAME, f"Moved to quarantine.\nID: {qid}")
            self.tree.set(self.tree.selection()[0], "s", "QUARANTINED")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(APPNAME, f"Could not move the file:\n{e}\n\nIs the program still running? Quit it first "
                                          "or restart the scanner with administrator rights.")

    def act_uninstall(self):
        f = self._cur()
        a = (f.action or {}) if f else {}
        if a.get("type") != "adb_uninstall":
            return
        if not messagebox.askyesno(APPNAME, f"Remove the app {a['pkg']} from the phone?\n\nSecure evidence first "
                                            "(screenshots, save the report) if you want to report this to the police."):
            return
        from .android import uninstall
        try:
            messagebox.showinfo(APPNAME, uninstall(a["adb"], a["serial"], a["pkg"]))
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(APPNAME, str(e))

    def act_open(self):
        f = self._cur()
        if not f:
            return
        p = (f.action or {}).get("path") or f.path
        if not p:
            return
        d = p if os.path.isdir(p) else os.path.dirname(p)
        try:
            if os_name() == "windows":
                if os.path.isfile(p):
                    subprocess.Popen(["explorer", "/select,", p])
                else:
                    os.startfile(d)  # type: ignore[attr-defined]
            elif os_name() == "macos":
                subprocess.Popen(["open", "-R", p] if os.path.isfile(p) else ["open", d])
            else:
                subprocess.Popen(["xdg-open", d])
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(APPNAME, str(e))

    def act_copy(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.detail.get("1.0", "end"))
        self._set_status("Text copied to the clipboard.")

    def show_quarantine(self):
        w = tk.Toplevel(self.root, bg=GRAY)
        w.title("Quarantine")
        w.geometry("720x360")
        lb = tk.Listbox(w, font=self.f_mono, relief="sunken", bd=2, bg=WHITE, selectbackground=NAVY)
        lb.pack(fill="both", expand=True, padx=6, pady=6)
        entries = []

        def fill():
            lb.delete(0, "end")
            entries[:] = quarantine.entries()
            for e in entries:
                lb.insert("end", f"{e['time']}  {e['original']}")
            if not entries:
                lb.insert("end", "(empty)")

        def sel():
            i = lb.curselection()
            return entries[i[0]] if i and entries else None

        def do_restore():
            e = sel()
            if e and messagebox.askyesno(APPNAME, f"Restore to\n{e['original']} ?", parent=w):
                try:
                    quarantine.restore(e["id"])
                except Exception as ex:  # noqa: BLE001
                    messagebox.showerror(APPNAME, str(ex), parent=w)
                fill()

        def do_delete():
            e = sel()
            if e and messagebox.askyesno(APPNAME, "Delete permanently? This cannot be undone.", parent=w):
                quarantine.delete(e["id"])
                fill()

        bf = tk.Frame(w, bg=GRAY)
        bf.pack(fill="x", padx=6, pady=(0, 6))
        self._btn(bf, "Restore", do_restore, w=14, h=1, bold=False).pack(side="left", padx=2)
        self._btn(bf, "Delete permanently", do_delete, w=18, h=1, bold=False).pack(side="left", padx=2)
        self._btn(bf, "Close", w.destroy, w=12, h=1, bold=False).pack(side="right", padx=2)
        fill()

    def show_cleanup(self):
        from . import cleanup
        android = getattr(self.ctx, "android", None) if self.ctx else None
        items = cleanup.plan(android=android)
        w = tk.Toplevel(self.root, bg=GRAY)
        w.title("Privacy cleanup")
        w.geometry("660x400")
        tk.Label(w, text="Thumbnail caches keep small copies of photos – also of photos that were deleted long ago.\n"
                         "Select what should be deleted. Deleting is permanent.", bg=GRAY, justify="left",
                 anchor="w").pack(fill="x", padx=8, pady=(8, 4))
        box = tk.Frame(w, bg=WHITE, relief="sunken", bd=2)
        box.pack(fill="both", expand=True, padx=8, pady=4)
        choice = {}
        if not items:
            tk.Label(box, text="Nothing to clean up.", bg=WHITE).pack(anchor="w", padx=6, pady=6)
        for it in items:
            v = tk.BooleanVar(value=it["id"] != "win-recycle")
            choice[it["id"]] = v
            tk.Checkbutton(box, text=it["text"], variable=v, bg=WHITE, activebackground=WHITE, anchor="w",
                           selectcolor=WHITE).pack(fill="x", padx=6, pady=(4, 0))
            tk.Label(box, text="      " + it["detail"], bg=WHITE, fg="#404040", anchor="w").pack(fill="x", padx=6)
        v_restart = tk.BooleanVar(value=False)
        if os_name() == "windows":
            tk.Checkbutton(w, text="Restart Windows Explorer if the cache is in use (the taskbar disappears for a moment)",
                           variable=v_restart, bg=GRAY, activebackground=GRAY, selectcolor=WHITE).pack(anchor="w", padx=8)

        def run_it():
            ids = {k for k, v in choice.items() if v.get()}
            if not ids:
                return
            if not messagebox.askyesno(APPNAME, "Delete the selected items permanently?", parent=w):
                return
            res = cleanup.execute(ids, items, restart_explorer=v_restart.get(), android=android)
            messagebox.showinfo(APPNAME, "\n".join(f"{a}: {b}" for a, b in res) or "Nothing was done.", parent=w)
            w.destroy()

        bf = tk.Frame(w, bg=GRAY)
        bf.pack(fill="x", padx=8, pady=8)
        self._btn(bf, "Delete selected", run_it, w=16, h=1, bold=False).pack(side="left")
        self._btn(bf, "Close", w.destroy, w=12, h=1, bold=False).pack(side="right")

    def combine_reports(self):
        from . import fleet
        paths = filedialog.askopenfilenames(title="Choose the JSON reports of your devices", filetypes=[("JSON report", "*.json")])
        if not paths:
            return
        out = filedialog.asksaveasfilename(title="Save combined report", defaultextension=".html",
                                           initialfile="SCS-Combined-Report.html", filetypes=[("HTML report", "*.html")])
        if not out:
            return
        try:
            n = fleet.merge(paths, out)
            self._set_status(f"Combined report of {n} devices saved: {out}")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(APPNAME, str(e))

    def show_about(self):
        w = tk.Toplevel(self.root)
        w.title(f"About {APPNAME}")
        w.configure(bg=GRAY)
        w.resizable(False, False)
        w.transient(self.root)
        tk.Label(w, text=" >_SCS ", bg="#000000", fg="#00FF00", font=(self.f_mono[0], 16, "bold")).pack(padx=16, pady=(16, 8))
        tk.Label(w, justify="left", bg=GRAY, text=(
            f"{APPNAME} {VERSION}\nby Sedic Code Studio\n\n"
            "Checks your own devices for spyware, malware, hidden files and redirected traffic.\n"
            "Open source under the Apache License 2.0.\n\n"
            "Contact: info@sediccodestudio.de\n"
            "Source code and help: github.com/SedicCodeStudio/scs-scanner\n\n"
            "Indicators: MVT / Amnesty International Security Lab, ECHAP, Zero Breach and others (see NOTICE).\n"
            f"Diagnostic log (contains no scan results): {log.LOG_FILE}")).pack(padx=16)
        result = tk.Label(w, text="", bg=GRAY, justify="left", fg="#000080")
        result.pack(padx=16, pady=6)
        bar = tk.Frame(w, bg=GRAY)
        bar.pack(pady=(4, 14))

        def check():
            result.config(text="Checking github.com …")
            from . import updates

            def job():
                text = updates.check()
                self.root.after(0, lambda: result.config(text=text))
            threading.Thread(target=job, daemon=True).start()

        def website():
            import webbrowser
            webbrowser.open("https://github.com/SedicCodeStudio/scs-scanner")
        self._btn(bar, "Check for updates", check, w=18, h=1).pack(side="left", padx=4)
        self._btn(bar, "Website", website, w=10, h=1).pack(side="left", padx=4)
        self._btn(bar, "Close", w.destroy, w=10, h=1).pack(side="left", padx=4)
        w.grab_set()

    def elevate(self):
        try:
            import ctypes
            script = os.path.abspath(sys.argv[0])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}"', None, 1)
            self.root.destroy()
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(APPNAME, str(e))


def _dpi_aware():
    """Sharp text on high-resolution Windows screens."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001 – older Windows versions
            pass


def main():
    _dpi_aware()
    log.start("window")
    root = tk.Tk()
    try:
        from .icon import ICON_PNG
        root._scs_icon = tk.PhotoImage(data=ICON_PNG)
        root.iconphoto(True, root._scs_icon)
    except Exception:  # noqa: BLE001 – an icon is not worth a crash
        pass

    def on_error(exc_type, exc, tb):
        path = log.crash(exc_type, exc, tb)
        messagebox.showerror(APPNAME, f"Unexpected error: {exc}\n\nDetails were saved to:\n{path}\n\n"
                                      "Please report it at github.com/SedicCodeStudio/scs-scanner/issues "
                                      "(attach the file – it contains no scan results).")
    root.report_callback_exception = on_error
    App(root)
    root.mainloop()
