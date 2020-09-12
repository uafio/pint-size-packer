# pint-size-packer
Minimalistic zlib packer for Windows x64 executables

This is just a tiny Proof-of-Concept for the ins-and-outs of Windows binary packers. It only supports small part of the PE file format features.

## Implementation Details
Input binaries are parsed and split into two main segments. First segment is the PE Headers segment, second segment is split between all section headers + section data pairs. Next, we merge and compress all sections together with the exception of the `.rsrc` section. This section can't be packed if the application have any resources (icons, menus, etc...). A [decompression stub](#decompression-stub) is attached to the application as an additional section which contains the code for the new EntryPoint.

## Decompression Stub
Here we are using some MSVC tricks to position all the necessary code and data together in a single section with no extern dependencies. This code is compiled as part of the packer (not packed/input) application. At runtime when the input application is analyzed, we load and parse the packer application to extract and implant this stub section into the input application.
As part of the packed application, the purpose of the decompression stub is to decompress the original compressed data, place the original sections to their original load addresses and perform Windows loader's resposibilities.

## Features
- [x] x64 Support
- [ ] x86 Support
- [ ] TLS Support
- [ ] .NET Support
- [ ] DLL Support
- [x] Hide Import Table 
- [x] Resolve Imports
- [x] Fix Relocations
- [x] Per section compression -- [release](https://github.com/uafio/pint-size-packer/releases/tag/0.1)

## Usage
```
> psp.exe
Usage: psp.exe <infile> <outfile>

> psp.exe psp.exe psp_packed.exe

> psp_packed.exe
Usage: psp_packed.exe <infile> <outfile>

> dir
            62,976 psp.exe
            43,008 psp_packed.exe
```
