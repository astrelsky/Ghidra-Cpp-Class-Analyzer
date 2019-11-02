Ghidra C++ Class and Run Time Type Information Analyzer
=======================================================

Building
--------

Prior to building, the GHIDRA_INSTALL_DIR environment variable and the version number in extension.properties must be correctly set.

The target versions settings are as follows:

* Ghidra_9.1: version=9.1
* Ghidra_9.2-DEV: version=9.2

Once the version has been correctly set, run the following command in a terminal of your choice.

`gradle buildExtension`

Upon completion the output will be located in the dist folder.

Installation
------------

Extract the archive to a destination folder of your choice.
Launch ghidra and from the project manager go to file->Install Extensions...
Click the + icon near the top right corner of the window.
Select the the path of the extracted Ghidra-Cpp-Class-Analyzer folder and select OK.
After restarting ghidra the plugin will be installed and ready for use.
You will know it has been successfully installed if the TypeInfo datatype appears within the BuiltInTypes datatype manager.

Features
--------

* GCC RTTI models and analysis.
* Vtable analysis and class namespace setting.
* Constructor/Destructor analysis.
* Reconstruction of class inheritance models for virtual multiple inheritance.

Supported Compilers
-------------------

* GCC  
* Clang  
* Visual Studio (Control Flow Guard (CFG) not supported)

Documentation
-------------

While documentation is not yet complete there is quite a bit of documentation
currently available. This documentation may be build by running gradle javadoc.

Information
-----------

This was initially built with the intention of having it merged into Ghidra.
As time went on it grew exponentially. There is still work needed to be done
regarding package paths, cleanup, documentation and testing. It it mostly
functional. All packages, class names, etc. subject to change.

The Visual Studio class analysis was hastily thrown together in two days.
Issues and minor oversights are to be expected.

Vtable Database
---------------

A cheap and lazy "database" has been implemented for virtual function tables.
It is mainly a proof of concept but is functional.
The provided json db file is just a collection of mangled strings for the
functions found in the vtables in libstdc++. To use simply add the ghidra_scripts
folder into Ghidra's scripts path, run the GccRtti analyzer and then run
parse_vtable_db.py. For best results run the parser before running the
C++ Class Analyzer.

Compatibility
-------------

It is compatible with current builds of 9.2, 9.1.

TODO
----

Implement an actual database to hold ClassTypeInfo instances for resolving of base classes
from external libraries.

License
---------

The stand alone release and source is licensed under the The MIT License (MIT).
