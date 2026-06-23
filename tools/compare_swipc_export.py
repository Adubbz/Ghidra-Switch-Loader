#!/usr/bin/env python3
"""
Compare a swipc .info reference against a GSL json export.

https://yls8.mtheall.com/ninupdates/reports.php

navigate to a switch 1 firmware version
example:
https://yls8.mtheall.com/ninupdates/reports.php?date=2026-04-07_01-04-36&sys=hac
then enter the global report list by date:
https://yls8.mtheall.com/ninupdates/titlelist.php?date=2026-04-07_01-04-36&sys=hac&reg=G
then save the "swipcgen_server_modern.info" corresponding the program you are comparing against (only the swipcgen_server_modern.info file of any sysmodule or program for kips it starts with FS_, NCM_)

Interface NAMES are intentionally ignored: both sides are expected to emit
interfaces in the same DISCOVERY ORDER, so interfaces are aligned positionally
(1st-vs-1st, 2nd-vs-2nd, ...). Within each interface, commands are matched by
command-id and their `lr` values compared.

Reports:
  * interface count (swipc vs export)
  * per-interface command count
  * any command-id present on one side but not the other
  * any command-id whose lr differs

Usage:
    python tools/compare_swipc_export.py ns_swipc.info json_output/NS_services.json
    python tools/compare_swipc_export.py ns_swipc.info NS_services.json --map > map.json

With --map: if (and only if) every lr matches, print a JSON ARRAY in OUR
export order pairing each interface's swipc NAME with our export's hash(es),
e.g.

    [
      { "swipc": "nn::sf::hipc::detail::IHipcManager",
        "_hash": "110f14166ba3f72c" },
      { "swipc": "nn::hid::IHidServer",
        "_hash": "0d9dc9f6dec24514",
        "_hash_alt": "cfe51e263f5c8dbe" }
    ]

An array (not a name-keyed object) is used because swipc reuses some
interface names for distinct interfaces, which an object would collapse.
This is the relabeling table for re-keying the hash database to swipc names
when interface order diverges. The report goes to stderr; the JSON to stdout.
"""
import sys
import re
import json


def parse_swipc(path):
    """Return ordered list of (interface_name, {cmd_id: lr_lowercase}).

    Empty (0-command) interface entries are dropped: swipc forward-declares
    out-interfaces as empty stubs and then re-lists them with real commands,
    so the empty stubs are duplicates that contribute no lr and only desync
    positional alignment.
    """
    ifaces = []
    cur_name = None
    cur_cmds = None
    iface_re = re.compile(r"^(\s*)'([^']+)':\s*\{")
    cmd_re = re.compile(r"^\s*(\d+):\s*\{(.*)\}\s*,?\s*$")
    lr_re = re.compile(r'"lr"\s*:\s*(0x[0-9A-Fa-f]+)')
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = iface_re.match(line)
            if m:
                indent, name = m.group(1), m.group(2)
                # col-0 entry is the program wrapper ('ns': {), not an interface
                if len(indent) == 0:
                    continue
                cur_name = name
                cur_cmds = {}
                ifaces.append((cur_name, cur_cmds))
                continue
            m = cmd_re.match(line)
            if m and cur_cmds is not None:
                cmd_id = int(m.group(1))
                lrm = lr_re.search(m.group(2))
                if lrm:
                    cur_cmds[cmd_id] = lrm.group(1).lower()
    return [(n, c) for (n, c) in ifaces if c]


def parse_export(path):
    """Return ordered list of (interface_name, {cmd_id: lr_lowercase}, hash)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    ifaces = []
    # single top-level program key (e.g. "fs")
    for prog_key, prog_val in data.items():
        if not isinstance(prog_val, dict):
            continue
        for iface_name, iface_val in prog_val.items():
            if not isinstance(iface_val, dict):
                continue  # skip scalar meta like program_identified
            if iface_name.startswith("_"):
                continue  # skip meta dicts like _invokes
            cmds = {}
            for cmd_key, cmd_val in iface_val.items():
                if not isinstance(cmd_val, dict):
                    continue  # skip _hash and other scalar meta
                try:
                    cmd_id = int(cmd_key)
                except ValueError:
                    continue
                lr = cmd_val.get("lr")
                if lr:
                    cmds[cmd_id] = str(lr).lower()
            # preserve every hash key (_hash, _hash_alt, ...) in file order
            hashes = {k: v for k, v in iface_val.items() if k.startswith("_hash")}
            if cmds:
                ifaces.append((iface_name, cmds, hashes))
    return ifaces


def emit_map(swipc, export, out):
    """Print, in OUR export order, a JSON ARRAY pairing each interface's swipc
    NAME with our _hash (and _hash_alt, ...). Interfaces are matched by
    lr-signature (content), so the correct swipc name is paired with our hash
    even when interface order diverges. An array (not a name-keyed object) is
    used because swipc reuses some interface names for distinct interfaces;
    an object would silently collapse those duplicates on parse."""
    # signature (frozenset of lrs) -> queue of swipc names, in swipc order
    sig_index = {}
    for name, cmds in swipc:
        sig_index.setdefault(frozenset(cmds.values()), []).append(name)

    entries = []
    for e_name, e_cmds, e_hashes in export:
        sig = frozenset(e_cmds.values())
        names = sig_index.get(sig)
        swipc_name = names.pop(0) if names else None
        if swipc_name is None:
            # no content match (grouping differs) -- surface, don't fabricate
            print("!! no swipc interface matches export '%s' by lr-signature"
                  % e_name, file=sys.stderr)
            swipc_name = e_name  # fall back to our own name, clearly visible
        entry = {"swipc": swipc_name}
        entry.update(e_hashes)  # _hash, _hash_alt, ... in original order
        entries.append(entry)

    json.dump(entries, out, indent=2, ensure_ascii=False)
    out.write("\n")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = set(a for a in sys.argv[1:] if a.startswith("--"))
    if len(args) != 2:
        print(__doc__)
        sys.exit(2)
    swipc_path, export_path = args
    map_mode = "--map" in flags
    # in --map mode the diagnostic report goes to stderr, JSON to stdout
    rep = sys.stderr if map_mode else sys.stdout

    swipc = parse_swipc(swipc_path)
    export = parse_export(export_path)

    def P(*a):
        print(*a, file=rep)

    P("=" * 72)
    P("swipc : %s  (%d interfaces, %d commands)"
      % (swipc_path, len(swipc), sum(len(c) for _, c in swipc)))
    P("export: %s  (%d interfaces, %d commands)"
      % (export_path, len(export), sum(len(c) for _, c, _h in export)))
    P("=" * 72)

    if len(swipc) != len(export):
        P("!! INTERFACE COUNT MISMATCH: swipc=%d export=%d"
          % (len(swipc), len(export)))
        P("   (positional alignment past the first divergence is unreliable)")
    P("")

    n = max(len(swipc), len(export))
    total_lr_mismatch = 0
    total_missing = 0      # in swipc, absent in export
    total_extra = 0        # in export, absent in swipc
    bad_ifaces = 0

    for i in range(n):
        s_name, s_cmds = swipc[i] if i < len(swipc) else (None, {})
        e_name, e_cmds = (export[i][0], export[i][1]) if i < len(export) else (None, {})

        if s_name is None:
            P("[%3d] export-only interface  '%s'  (%d cmds) -- no swipc counterpart"
              % (i, e_name, len(e_cmds)))
            bad_ifaces += 1
            total_extra += len(e_cmds)
            continue
        if e_name is None:
            P("[%3d] swipc-only interface   '%s'  (%d cmds) -- no export counterpart"
              % (i, s_name, len(s_cmds)))
            bad_ifaces += 1
            total_missing += len(s_cmds)
            continue

        s_ids = set(s_cmds)
        e_ids = set(e_cmds)
        missing = sorted(s_ids - e_ids)             # swipc has, export lacks
        extra = sorted(e_ids - s_ids)               # export has, swipc lacks
        lr_diffs = sorted(cid for cid in (s_ids & e_ids) if s_cmds[cid] != e_cmds[cid])

        if not missing and not extra and not lr_diffs and len(s_cmds) == len(e_cmds):
            continue  # perfect interface -- stay quiet

        bad_ifaces += 1
        total_missing += len(missing)
        total_extra += len(extra)
        total_lr_mismatch += len(lr_diffs)

        P("[%3d] swipc '%s' (%d cmds)  vs  export '%s' (%d cmds)"
          % (i, s_name, len(s_cmds), e_name, len(e_cmds)))
        if missing:
            P("      MISSING in export (cmd-ids): %s"
              % ", ".join(str(c) for c in missing))
        if extra:
            P("      EXTRA in export (cmd-ids):   %s"
              % ", ".join(str(c) for c in extra))
        for cid in lr_diffs:
            P("      LR MISMATCH cmd %s: swipc %s != export %s"
              % (cid, s_cmds[cid], e_cmds[cid]))

    # Global lr-set check: distinguishes a pure ORDERING difference (same
    # lrs, arranged differently) from a real DATA difference (lrs present on
    # one side only). If positional pairing is noisy but these sets match,
    # every command was recovered -- only the interface order differs.
    swipc_lrs = set(lr for _, c in swipc for lr in c.values())
    export_lrs = set(lr for _, c, _h in export for lr in c.values())
    only_swipc = swipc_lrs - export_lrs
    only_export = export_lrs - swipc_lrs

    P("")
    P("=" * 72)
    P("POSITIONAL SUMMARY (interfaces aligned by discovery order)")
    P("  interfaces with differences : %d / %d" % (bad_ifaces, n))
    P("  commands missing in export  : %d" % total_missing)
    P("  commands extra in export    : %d" % total_extra)
    P("  lr mismatches               : %d" % total_lr_mismatch)
    P("")
    P("GLOBAL lr-SET CHECK (order-independent)")
    P("  unique lrs  swipc=%d  export=%d" % (len(swipc_lrs), len(export_lrs)))
    P("  lrs only in swipc (missing) : %d" % len(only_swipc))
    for lr in sorted(only_swipc):
        P("      %s" % lr)
    P("  lrs only in export (extra)  : %d" % len(only_export))
    for lr in sorted(only_export):
        P("      %s" % lr)
    P("")
    positional_ok = (len(swipc) == len(export) and bad_ifaces == 0)
    data_ok = (not only_swipc and not only_export)
    if positional_ok and data_ok:
        verdict = "FULL PARITY (identical, same order)"
    elif data_ok:
        verdict = "DATA PARITY -- every lr matched; only interface ORDER differs"
    else:
        verdict = "DATA DIFFERENCES -- some lrs present on one side only"
    P("  RESULT: %s" % verdict)
    P("=" * 72)

    if map_mode:
        #if not data_ok:
        #    print("!! --map refused: lrs do not all match (data differences). "
        #          "Resolve those first.", file=sys.stderr)
        #    sys.exit(1)
        emit_map(swipc, export, sys.stdout)
        sys.exit(0)

    sys.exit(0 if (positional_ok and data_ok) else 1)


if __name__ == "__main__":
    main()
