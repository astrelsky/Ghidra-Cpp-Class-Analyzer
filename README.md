[![Run tests](https://github.com/astrelsky/Ghidra-Cpp-Class-Analyzer/actions/workflows/test.yml/badge.svg)](https://github.com/astrelsky/Ghidra-Cpp-Class-Analyzer/actions/workflows/test.yml)  
Ghidra C++ Class and Run Time Type Information Analyzer
=======================================================

API Documentation
-----------------

A fully built and linked version of the documentation is available at <https://astrelsky.github.io/Ghidra-Cpp-Class-Analyzer>.

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

Inheritance Modeling via the Type Info Tree
-------------------------------------------

![Capture](https://user-images.githubusercontent.com/46897303/86498580-62295580-bd54-11ea-9434-d1b3e6e40a4c.PNG)

Class Type Info Color Coding
----------------------------

![#FFFF00](https://via.placeholder.com/15/ffff00/000000?text=+) - Nested Class  
![#28a745](https://via.placeholder.com/15/28a745/000000?text=+) - Basic Class  
![#d73a49](https://via.placeholder.com/15/d73a49/000000?text=+) - Abstract Class  
![#0366d6](https://via.placeholder.com/15/0366d6/000000?text=+) - Virtual Class  
![#6f42c1](https://via.placeholder.com/15/6f42c1/000000?text=+) - Virtual Abstract Class

CppClassAnalyzerGhidraScript
----------------------------

Want to make a GhidraScript with easy access to the ClassTypeInfoManager for the currentProgram? Try extending the CppClassAnalyzerGhidraScript class instead of GhidraScript. Unfortunately this is currently only possible for scripts written in Java.

Fill Out Class Decompiler Action
--------------------------------

Right clicking within the decompiler window in a `__thiscall` function with which a ClassTypeInfo exists will contain an action to fill out the class. It behaves similarly to the fill out structure action accept class members are determined via calls to other `__thiscall` functions.

Dynamic RTTI Handling
---------------------

For GNU binaries a project archive will need to be created to provide data required for analysis. Each library containing dynamic RTTI will need to be analyzed and copied into the project archive via the TypeInfoTree prior to analyzing the program. In the future an archive wil be distributed for libstdc++.

TODO
----

* Graphing
* Type Info Tree filter
* Help Documentation
