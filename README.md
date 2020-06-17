Ghidra C++ Class and Run Time Type Information Analyzer
=======================================================

Experimental
------------

This branch is experimental and is still in development. Issues are to be expected and feedback is always welcome.

Building
--------

Run the following command in a terminal of your choice.

`gradle buildExtension`

Upon completion the output will be located in the dist folder.

Installation
------------

Extract the archive to a destination folder of your choice.
Launch ghidra and from the project manager go to `file->Install Extensions...`
Click the + icon near the top right corner of the window.
Select the the path of the extracted Ghidra-Cpp-Class-Analyzer folder and select OK.
After restarting ghidra open the CodeBrowser and go to `file->Configure...->Experimental` and select `ClassTypeInfoManagerPlugin`. Restart the CodeBrowser to allow the analyzers to be refreshed.

Features
--------

* GCC RTTI models and analysis.
* Vtable analysis and class namespace setting.
* Constructor/Destructor analysis.
* Reconstruction of class inheritance models for virtual multiple inheritance.
* Tree style display of inheritance hierarchy.

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
functional. All packages, class names, etc. subject to change.

The Visual Studio class analysis was hastily thrown together in two days.
Issues and minor oversights are to be expected.

Dynamic RTTI Handling
---------------------

For GNU binaries a project archive will need to be created to provide data required for analysis. Each library containing dynamic RTTI will need to be analyzed and copied into the project archive via the TypeInfoTree prior to analyzing the program. In the future an archive wil be distributed for libstdc++.

Compatibility
-------------

It is compatible with current builds of 9.2

TODO
----

Cleanup, bugfixes and fillout new documentation.

License
---------

The stand alone release and source is licensed under the The MIT License (MIT).
