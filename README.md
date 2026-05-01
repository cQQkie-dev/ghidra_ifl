Ghidra version of hasherezade's [ida_ifl](https://github.com/hasherezade/ida_ifl) (Interactive Functions List).
Original features were preserved and extended with some extra functionality:

* Import/export for and from other hasherezade tools like [pe-bear](https://github.com/hasherezade/pe-bear), [tiny_tracer](https://github.com/hasherezade/tiny_tracer), [pe-sieve](https://github.com/hasherezade/pe-sieve) in `.tag` and `csv` formats
* exports specifically for fast iterations of static analysis to dynamic tracing with `tiny_tracer` by providing .params.txt and .func.csv exports
* fast filtering and selection of functions of interest with regex, as well as UI interaction for selecting view subsets of functions
* written and released for Ghidra 12+ API
* Ghidra extension written in Java (dockable window, domain object listener for function and symbol changes, UI theme detection for flatlaf (light/dark), color palettes)
* `ghidra_scripts/GhidraIFL_FunctionList.py`: standalone PyGhidra script as alternative (not dockable, no full Ghidra API integration, ...)
