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
* Visual Studio

Information
-----------

This was initially built with the intention of having it merged into Ghidra.
As time went on it grew exponentially. There is still work needed to be done
regarding package paths, cleanup, documentation and testing. It it mostly
functional. All packages, class names subject to change.

The Visual Studio class analysis was hastily thrown together in two days.
Issues and minor oversights are to be expected.

Compatibility
-------------

It is compatible with current builds of 9.1.  
9.0.4 compatibility is currently unknown.

License
---------

The stand alone release and source is licensed under the The MIT License (MIT).
