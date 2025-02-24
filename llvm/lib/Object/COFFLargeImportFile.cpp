//===- COFFImportFile.cpp - COFF large import file implementation ---------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Object/COFFLargeImportFile.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Error.h"

using namespace llvm::COFF;
using namespace llvm::object;
using namespace llvm;

namespace llvm {
namespace object {

StringRef COFFLargeImportFile::getFileFormatName() const {
  switch (getMachine()) {
  case COFF::IMAGE_FILE_MACHINE_I386:
    return "COFF-large-import-file-i386";
  case COFF::IMAGE_FILE_MACHINE_AMD64:
    return "COFF-large-import-file-x86-64";
  case COFF::IMAGE_FILE_MACHINE_ARMNT:
    return "COFF-large-import-file-ARM";
  case COFF::IMAGE_FILE_MACHINE_ARM64:
    return "COFF-large-import-file-ARM64";
  case COFF::IMAGE_FILE_MACHINE_ARM64EC:
    return "COFF-large-import-file-ARM64EC";
  case COFF::IMAGE_FILE_MACHINE_ARM64X:
    return "COFF-large-import-file-ARM64X";
  default:
    return "COFF-large-import-file-<unknown arch>";
  }
}

StringRef COFFLargeImportFile::getSymbolName() const {
  const COFFLargeImportHeader *hdr = getCOFFLargeImportHeader();
  return Data.getBuffer().substr(sizeof(*hdr), hdr->SizeOfInternalSymbolName);
}

StringRef COFFLargeImportFile::getExportName() const {
  // Explicit export name is given when external symbol name size is not zero, otherwise external name matches the symbol name
  const COFFLargeImportHeader *hdr = getCOFFLargeImportHeader();
  if (hdr->SizeOfExternalSymbolName)
    return Data.getBuffer().substr(sizeof(*hdr) + hdr->SizeOfInternalSymbolName + hdr->SizeOfDllNameHint, hdr->SizeOfExternalSymbolName);
  return getSymbolName();
}

StringRef COFFLargeImportFile::getDllName() const {
  const COFFLargeImportHeader *hdr = getCOFFLargeImportHeader();
  return Data.getBuffer().substr(sizeof(*hdr) + hdr->SizeOfInternalSymbolName, hdr->SizeOfDllNameHint);
}

Error COFFLargeImportFile::printSymbolName(raw_ostream &OS, DataRefImpl Symb) const {
  switch (Symb.p) {
  case ImpSymbol:
    OS << "__imp_";
    break;
  }
  OS << getSymbolName();
  return Error::success();
}

} // namespace object
} // namespace llvm