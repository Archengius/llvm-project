//===-- COFFImportDumper.cpp - COFF import library dumper -------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file implements the COFF import library dumper for llvm-readobj.
///
//===----------------------------------------------------------------------===//

#include "llvm/BinaryFormat/COFF.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/COFFImportFile.h"
#include "llvm/Support/ScopedPrinter.h"
// <COFF_LARGE_EXPORTS>
#include "llvm/Object/COFFLargeImportFile.h"
// </COFF_LARGE_EXPORTS>

using namespace llvm::object;

namespace llvm {

void dumpCOFFImportFile(const COFFImportFile *File, ScopedPrinter &Writer) {
  Writer.startLine() << '\n';
  Writer.printString("File", File->getFileName());
  Writer.printString("Format", File->getFileFormatName());

  const coff_import_header *H = File->getCOFFImportHeader();
  switch (H->getType()) {
  case COFF::IMPORT_CODE:  Writer.printString("Type", "code"); break;
  case COFF::IMPORT_DATA:  Writer.printString("Type", "data"); break;
  case COFF::IMPORT_CONST: Writer.printString("Type", "const"); break;
  }

  switch (H->getNameType()) {
  case COFF::IMPORT_ORDINAL:
    Writer.printString("Name type", "ordinal");
    break;
  case COFF::IMPORT_NAME:
    Writer.printString("Name type", "name");
    break;
  case COFF::IMPORT_NAME_NOPREFIX:
    Writer.printString("Name type", "noprefix");
    break;
  case COFF::IMPORT_NAME_UNDECORATE:
    Writer.printString("Name type", "undecorate");
    break;
  case COFF::IMPORT_NAME_EXPORTAS:
    Writer.printString("Name type", "export as");
    break;
  }

  if (H->getNameType() != COFF::IMPORT_ORDINAL)
    Writer.printString("Export name", File->getExportName());

  for (const object::BasicSymbolRef &Sym : File->symbols()) {
    raw_ostream &OS = Writer.startLine();
    OS << "Symbol: ";
    cantFail(Sym.printName(OS));
    OS << "\n";
  }
}

// <COFF_LARGE_EXPORTS>
void dumpCOFFLargeImportFile(const COFFLargeImportFile *File, ScopedPrinter &Writer) {
  Writer.startLine() << '\n';
  Writer.printString("File", File->getFileName());
  Writer.printString("Format", File->getFileFormatName());

  const COFFLargeImportHeader *H = File->getCOFFLargeImportHeader();
  switch (H->Type) {
  case LARGE_LOADER_IMPORT_TYPE_INVALID:  Writer.printString("Type", "invalid"); break;
  case LARGE_LOADER_IMPORT_TYPE_CODE:  Writer.printString("Type", "code"); break;
  case LARGE_LOADER_IMPORT_TYPE_DATA:  Writer.printString("Type", "data"); break;
  case LARGE_LOADER_IMPORT_TYPE_WILDCARD:  Writer.printString("Type", "wildcard"); break;
  default: Writer.printString("Type", "unknown"); break;
  }
  // Print flags set on the import
  {
    SmallVector<StringRef, 8> SymbolFlags;
    if ((H->Flags & LARGE_LOADER_IMPORT_FLAGS_WILDCARD_LOOKUP_WIN32_EXPORT_DIRECTORY) != 0)
      SymbolFlags.push_back("lookup-win32-exports");
    if ((H->Flags & LARGE_LOADER_IMPORT_FLAGS_SYNTHETIC) != 0)
      SymbolFlags.push_back("synthetic");
    Writer.printString("Flags", join(SymbolFlags, " "));
  }
  const StringRef DllName = File->getDllName();
  Writer.printString("Symbol name", File->getSymbolName());
  Writer.printString("Dll name", DllName.empty() ? "<wildcard>" : DllName);
  Writer.printString("Export name", File->getExportName());

  for (const object::BasicSymbolRef &Sym : File->symbols()) {
    raw_ostream &OS = Writer.startLine();
    OS << "Symbol: ";
    cantFail(Sym.printName(OS));
    OS << "\n";
  }
}
// </COFF_LARGE_EXPORTS>

} // namespace llvm
