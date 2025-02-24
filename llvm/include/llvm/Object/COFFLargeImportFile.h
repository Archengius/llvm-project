//===- COFFLargeImportFile.h - COFF large import file implementation -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// COFF short import file is a special kind of file which contains
// only symbol names for DLL-exported symbols. This class implements
// exporting of Symbols to create libraries and a SymbolicFile
// interface for the file type.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBJECT_COFFLARGEIMPORTFILE_H
#define LLVM_OBJECT_COFFLARGEIMPORTFILE_H

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/MemoryBufferRef.h"
#include "llvm/Object/COFFLargeImport.h"

namespace llvm {
namespace object {

class COFFLargeImportFile : public SymbolicFile {
private:
  enum SymbolIndex { ImpSymbol, ThunkSymbol };
public:
  COFFLargeImportFile(MemoryBufferRef Source)
      : SymbolicFile(ID_COFFLargeImportFile, Source) {}

  static bool classof(Binary const *V) { return V->IsLargeCOFFImportFile(); }

  void moveSymbolNext(DataRefImpl &Symb) const override { ++Symb.p; }

  Error printSymbolName(raw_ostream &OS, DataRefImpl Symb) const override;

  Expected<uint32_t> getSymbolFlags(DataRefImpl Symb) const override {
    return SymbolRef::SF_Global;
  }

  basic_symbol_iterator symbol_begin() const override {
    return BasicSymbolRef(DataRefImpl(), this);
  }

  basic_symbol_iterator symbol_end() const override {
    DataRefImpl Symb;
    if (isData())
      Symb.p = ImpSymbol + 1;
    else
      Symb.p = ThunkSymbol + 1;
    return BasicSymbolRef(Symb, this);
  }

  bool is64Bit() const override { return false; }

  const COFFLargeImportHeader *getCOFFLargeImportHeader() const {
    return reinterpret_cast<const object::COFFLargeImportHeader *>(
        Data.getBufferStart());
  }

  uint16_t getMachine() const { return getCOFFLargeImportHeader()->Machine; }

  StringRef getSymbolName() const;
  StringRef getFileFormatName() const;
  StringRef getExportName() const;
  StringRef getDllName() const;
private:
  bool isData() const {
    return getCOFFLargeImportHeader()->Type == LARGE_LOADER_IMPORT_TYPE_DATA;
  }
};

} // namespace object
} // namespace llvm

#endif
