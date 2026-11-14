# Ghidra Switch Loader

A loader for Ghidra supporting a variety of Nintendo Switch file formats.

## Building

- Ensure you have ``JAVA_HOME`` set to the path of your JDK 25 installation (Ghidra 12.2 requires JDK 25).
- Set ``GHIDRA_INSTALL_DIR`` to your Ghidra install directory. This can be done in one of the following ways:
  - **Windows**: Running ``set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>``
  - **macos/Linux**: Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
  - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``
  - Adding ``GHIDRA_INSTALL_DIR`` to your Windows environment variables.
- Run ``./gradlew``
- You'll find the output zip file inside `/dist`

## Installation

- Start Ghidra and use the "Install Extensions" dialog (``File -> Install Extensions...``).
- Press the ``+`` button in the upper right corner.
- Select the zip file in the file browser, then restart Ghidra.

## Linking imports across modules

A game or applet's ExeFS is made up of several modules (`rtld`, `main`, `subsdk0`..`subsdk9`, `sdk`)
that rtld links into one process. Imported on its own, each module leaves every function it
imports from the others as an unresolved stub in `<EXTERNAL>`.

The **(Switch) Module Import Resolver** analyzer links those imports to the modules that define
them. For example, `main`'s calls into nnSdk end up in an `sdk` library, its EGL calls in the
library of the subsdk that exports them, and *Go To* on such an external opens that module at
the function.

### Usage

1. Import all the ExeFS modules of one title into the **same project folder**, keeping their
   file names (`main`, `subsdk0`, ..., `sdk`; a `.nso` extension is fine too). Use one folder
   per title so modules of different titles are never linked together.
2. Analyze any of them as usual. The analyzer is enabled by default and runs early in
   auto-analysis.

The siblings don't need to be analyzed first: their exports are the symbols the loader
creates at import time. The module being linked, however, needs its imports to exist as
functions in `<EXTERNAL>`. In `main` they usually do straight after import. In most `subsdk`
and `sdk` modules the imported symbols are untyped, so they only become functions during
auto-analysis. The analyzer runs right after that point, so normal auto-analysis covers both
cases.

**Programs that were already analyzed**, or modules imported after their siblings, can be
(re)linked at any time:

- *Analysis → One Shot → (Switch) Module Import Resolver*, or
- run the script `ResolveSwitchModuleImports.java` (Script Manager, category *Nintendo Switch*).

This also handles imports that the demangler has already moved into namespaces
(`<EXTERNAL>::nn::fs::…`). They are matched by their original (mangled) name, and their
namespace path is recreated under the target library. Running it again is safe: imports that
were already linked stay where they are, and only imports still in `<EXTERNAL>` are looked up.
If it reports *nothing to resolve* for a module that was never analyzed, analyze that module
first (see above).

**Headless**, for example to link every already-analyzed module in a folder:

```sh
analyzeHeadless <projectDir> <projectName>/<titleFolder> -process -noanalysis \
    -postScript ResolveSwitchModuleImports.java
```

Script arguments (both optional):

- `<order>`: comma-separated sibling names in search order, replacing the default.
- `-v`: list every linked import, grouped by library.

### Search order

An import is linked to the first module in the search order that exports it, following rtld's
global lookup in load order. Only the module's dynamic exports count, i.e. the names the
loader created, not labels added later by analysis:

```
main, subsdk0, subsdk1, ..., subsdk9, sdk
```

The module being analyzed is skipped. You can change the order in *Analysis Options →
(Switch) Module Import Resolver → Module search order*. This is also how to make it work with
modules that were renamed on import (e.g. `game_main,game_sdk`).

### Checking the result

- The analysis log (or the script output) has a summary per program:

  ```
  Resolving External Symbols of [/main] - Summary
      436 external symbols resolved, 0 remain unresolved
      [subsdk0] -> /subsdk0, 21 new symbols resolved
      [subsdk1] -> /subsdk1, 1 new symbols resolved
      [sdk] -> /sdk, 414 new symbols resolved
  ```

- In the *Symbol Tree*, *Imports* now has one library per sibling module, and
  *Window → External Programs* shows each library bound to its project file.

### Notes

- Each sibling module becomes a library named after its project file. The loader also adds
  libraries named after the module's `DT_NEEDED` entries (e.g. `nnSdk.nss`). Those stay
  unbound ("missing"). They don't match the file names, and rtld doesn't use them to look up
  symbols.
- A library path that you set yourself in *External Programs* is kept as it is.
- Libraries this resolver creates but that end up with no imports are removed again.
- Sysmodules (single `main` NSO, KIPs) have no sibling modules, so the analyzer finds nothing
  to link and changes nothing.
- Sibling programs are opened read-only and only while the resolver runs. The program being
  analyzed is the only one modified.
- Requires Ghidra 12.2 or later (library search ordinals).
