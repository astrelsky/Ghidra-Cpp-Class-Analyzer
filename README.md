Ghidra C++ Class and Run Time Type Information Analyzer
=======================================================

Features
---------

* GCC RTTI models and analysis.
* Vtable analysis and class namespace setting.
* Constructor/Destructor analysis.
* Reconstruction of class inheritance models for virtual multiple inheritance.

Supported Compilers
-------------------

* GCC  
* Clang  
* Visual Studio (Control Flow Guard (CFG) not supported)

Information
-----------

This was initially built with the intention of having it merged into Ghidra.
As time went on it grew exponentially. There is still work needed to be done
regarding package paths, cleanup, documentation and testing. It it mostly
functional. All packages, class names subject to change.

The Visual Studio class analysis was hastily thrown together in two days.
Issues and minor oversights are to be expected.

Vtable Database
---------------

A cheap and lazy "database" has been implemented for virtual function tables.
It is mainly a proof of concept but it is functional.
The provided json db file is just a collection of mangled strings for the
functions found in the vtables in libstdc++. To use simply add the ghidra_scripts
folder into Ghidra's scripts path, run the GccRtti analyzer and then run
parse_vtable_db.py. For best result run the parser before running the
C++ Class Analyzer.

Compatibility
-------------

It is compatible with current builds of 9.1 as well as 9.0.4

License
---------

The stand alone release and source is licensed under the The MIT License (MIT).
