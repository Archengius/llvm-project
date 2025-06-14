//===- DLL.h ----------------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLD_COFF_DLL_H
#define LLD_COFF_DLL_H

#include "Chunks.h"
#include "Symbols.h"

namespace lld::coff {

// Windows-specific.
// IdataContents creates all chunks for the DLL import table.
// You are supposed to call add() to add symbols and then
// call create() to populate the chunk vectors.
class IdataContents {
public:
  void add(DefinedImportData *sym) { imports.push_back(sym); }
  bool empty() { return imports.empty(); }

  void create(COFFLinkerContext &ctx);

  std::vector<DefinedImportData *> imports;
  std::vector<Chunk *> dirs;
  std::vector<Chunk *> lookups;
  std::vector<Chunk *> addresses;
  std::vector<Chunk *> hints;
  std::vector<Chunk *> dllNames;
  std::vector<Chunk *> auxIat;
  std::vector<Chunk *> auxIatCopy;
};

// <COFF_LARGE_EXPORTS>
class LargeLoaderImportDataContents {
public:
  void setupLargeLoaderDllOrder(COFFLinkerContext &ctx, int maxLoadOrder) const;
  void setupLargeLoaderExportDirectoryInitializer(SymbolTable &symtab);
  void setupLargeLoaderImportDirectoryInitializer(SymbolTable &symtab);
  void setupLargeLoaderDllImportDependencies(SymbolTable &symtab, const std::set<StringRef> &dllNameDependencies);
  void createLargeIdataChunks(SymbolTable &symtab, const std::vector<LargeImportData *> &allLargeImports, std::vector<Chunk *> &chunks);

  void createLargeLoaderDllImport(SymbolTable &symtab, StringRef dllName);
  ImportFile *createLoaderImport(SymbolTable &symtab, StringRef symbolName);
  void createStaticCallbackChunk(SymbolTable &symtab, StringRef name, ImportFile *callbackImport, Defined *callbackParameterSymbol, bool isTerminator = false);
  Chunk *findOrCreateNameChunk(StringRef name);

  std::vector<std::unique_ptr<MemoryBuffer>> loaderImportData;
  std::vector<std::unique_ptr<MemoryBuffer>> dllImportData;
  std::map<StringRef, size_t> importedDllNameToExportSectionIndex;

  // Chunks that will need to be appended to different sections of the final executable
  // Note that on hybrid binaries (ARM64X), this will contain both ARM64 and ARM64EC chunks
  std::vector<Chunk *> textChunks;
  std::vector<Chunk *> initializerChunks;
  std::vector<Chunk *> terminatorChunks;
  // On hybrid CPPE images, exports will be very similar between ARM64 and ARM64EC compiled code, so we can massively reduce
  // the size of the final image by reusing the name chunks across both targets
  std::vector<Chunk *> nameChunks;
  std::map<StringRef, Chunk *> nameChunkLookup;
};

class LargeLoaderExportDataContents {
public:
  void createStubEdataChunksForLargeLoader(SymbolTable &symtab, std::vector<Chunk *> &chunks) const;
  void createLargeEdataChunks(SymbolTable &symtab, std::vector<Chunk *> &chunks);
  Chunk *findOrCreateNameChunk(StringRef name);

  // On hybrid CPPE images, exports will be very similar between ARM64 and ARM64EC compiled code, so we can massively reduce
  // the size of the final image by reusing the name chunks across both targets
  std::vector<Chunk *> nameChunks;
  std::map<StringRef, Chunk *> nameChunkLookup;
};
// </COFF_LARGE_EXPORTS>

// Windows-specific.
// DelayLoadContents creates all chunks for the delay-load DLL import table.
class DelayLoadContents {
public:
  DelayLoadContents(COFFLinkerContext &ctx) : ctx(ctx) {}
  void add(DefinedImportData *sym) { imports.push_back(sym); }
  bool empty() { return imports.empty(); }
  void create();
  std::vector<Chunk *> getChunks();
  std::vector<Chunk *> getDataChunks();
  ArrayRef<Chunk *> getCodeChunks() { return thunks; }
  ArrayRef<Chunk *> getCodePData() { return pdata; }
  ArrayRef<Chunk *> getCodeUnwindInfo() { return unwindinfo; }
  ArrayRef<Chunk *> getAuxIat() { return auxIat; }
  ArrayRef<Chunk *> getAuxIatCopy() { return auxIatCopy; }

  uint64_t getDirRVA() { return dirs[0]->getRVA(); }
  uint64_t getDirSize();

private:
  Chunk *newThunkChunk(DefinedImportData *s, Chunk *tailMerge);
  Chunk *newTailMergeChunk(SymbolTable &symtab, Chunk *dir);
  Chunk *newTailMergePDataChunk(SymbolTable &symtab, Chunk *tm);

  std::vector<DefinedImportData *> imports;
  std::vector<Chunk *> dirs;
  std::vector<Chunk *> moduleHandles;
  std::vector<Chunk *> addresses;
  std::vector<Chunk *> names;
  std::vector<Chunk *> hintNames;
  std::vector<Chunk *> thunks;
  std::vector<Chunk *> pdata;
  std::vector<Chunk *> unwindinfo;
  std::vector<Chunk *> dllNames;
  std::vector<Chunk *> auxIat;
  std::vector<Chunk *> auxIatCopy;

  COFFLinkerContext &ctx;
};

// Create all chunks for the DLL export table.
void createEdataChunks(SymbolTable &symtab, std::vector<Chunk *> &chunks);
} // namespace lld::coff

#endif
