//===- InputFiles.h ---------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLD_COFF_INPUT_FILES_H
#define LLD_COFF_INPUT_FILES_H

#include "Config.h"
#include "lld/Common/LLVM.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/BinaryFormat/Magic.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/StringSaver.h"
#include <memory>
#include <set>
#include <vector>

namespace llvm {
struct DILineInfo;
namespace pdb {
class DbiModuleDescriptorBuilder;
class NativeSession;
}
namespace lto {
class InputFile;
}
}

namespace lld {
class DWARFCache;

namespace coff {
class COFFLinkerContext;

const COFFSyncStream &operator<<(const COFFSyncStream &, const InputFile *);

std::vector<MemoryBufferRef> getArchiveMembers(COFFLinkerContext &,
                                               llvm::object::Archive *file);

using llvm::COFF::IMAGE_FILE_MACHINE_UNKNOWN;
using llvm::COFF::MachineTypes;
using llvm::object::Archive;
using llvm::object::COFFObjectFile;
using llvm::object::COFFSymbolRef;
using llvm::object::coff_import_header;
using llvm::object::coff_section;

class Chunk;
class Defined;
class DefinedImportData;
class DefinedImportThunk;
class DefinedRegular;
class ImportThunkChunk;
class ImportThunkChunkARM64EC;
class SectionChunk;
class Symbol;
class SymbolTable;
class Undefined;
class TpiSource;
// <COFF_LARGE_EXPORTS>
class DefinedLargeImport;
class DefinedLargeImportThunk;
// </COFF_LARGE_EXPORTS>

// The root class of input files.
class InputFile {
public:
  enum Kind {
    ArchiveKind,
    ObjectKind,
    PDBKind,
    ImportKind,
    BitcodeKind,
    // <COFF_LARGE_EXPORTS> Added LargeImportKind
    DLLKind,
    LargeImportKind
    // </COFF_LARGE_EXPORTS>
  };
  Kind kind() const { return fileKind; }
  virtual ~InputFile() {}

  // Returns the filename.
  StringRef getName() const { return mb.getBufferIdentifier(); }

  // Reads a file (the constructor doesn't do that).
  virtual void parse() = 0;

  // Returns the CPU type this file was compiled to.
  virtual MachineTypes getMachineType() const {
    return IMAGE_FILE_MACHINE_UNKNOWN;
  }

  MemoryBufferRef mb;

  // An archive file name if this file is created from an archive.
  StringRef parentName;

  // Returns .drectve section contents if exist.
  StringRef getDirectives() { return directives; }

  SymbolTable &symtab;

protected:
  InputFile(SymbolTable &s, Kind k, MemoryBufferRef m, bool lazy = false)
      : mb(m), symtab(s), fileKind(k), lazy(lazy) {}

  StringRef directives;

private:
  const Kind fileKind;

public:
  // True if this is a lazy ObjFile or BitcodeFile.
  bool lazy = false;
};

// .lib or .a file.
class ArchiveFile : public InputFile {
public:
  explicit ArchiveFile(COFFLinkerContext &ctx, MemoryBufferRef m);
  static bool classof(const InputFile *f) { return f->kind() == ArchiveKind; }
  void parse() override;

  // Enqueues an archive member load for the given symbol. If we've already
  // enqueued a load for the same archive member, this function does nothing,
  // which ensures that we don't load the same member more than once.
  void addMember(const Archive::Symbol &sym);

private:
  std::unique_ptr<Archive> file;
  llvm::DenseSet<uint64_t> seen;
};

// .obj or .o file. This may be a member of an archive file.
class ObjFile : public InputFile {
public:
  static ObjFile *create(COFFLinkerContext &ctx, MemoryBufferRef mb,
                         bool lazy = false);
  explicit ObjFile(SymbolTable &symtab, COFFObjectFile *coffObj, bool lazy);

  static bool classof(const InputFile *f) { return f->kind() == ObjectKind; }
  void parse() override;
  void parseLazy();
  MachineTypes getMachineType() const override;
  ArrayRef<Chunk *> getChunks() { return chunks; }
  ArrayRef<SectionChunk *> getDebugChunks() { return debugChunks; }
  ArrayRef<SectionChunk *> getSXDataChunks() { return sxDataChunks; }
  ArrayRef<SectionChunk *> getGuardFidChunks() { return guardFidChunks; }
  ArrayRef<SectionChunk *> getGuardIATChunks() { return guardIATChunks; }
  ArrayRef<SectionChunk *> getGuardLJmpChunks() { return guardLJmpChunks; }
  ArrayRef<SectionChunk *> getGuardEHContChunks() { return guardEHContChunks; }
  ArrayRef<Symbol *> getSymbols() { return symbols; }

  MutableArrayRef<Symbol *> getMutableSymbols() { return symbols; }

  ArrayRef<uint8_t> getDebugSection(StringRef secName);

  // Returns a Symbol object for the symbolIndex'th symbol in the
  // underlying object file.
  Symbol *getSymbol(uint32_t symbolIndex) {
    return symbols[symbolIndex];
  }

  // Returns the underlying COFF file.
  COFFObjectFile *getCOFFObj() { return coffObj.get(); }

  // Add a symbol for a range extension thunk. Return the new symbol table
  // index. This index can be used to modify a relocation.
  uint32_t addRangeThunkSymbol(Symbol *thunk) {
    symbols.push_back(thunk);
    return symbols.size() - 1;
  }

  void includeResourceChunks();

  bool isResourceObjFile() const { return !resourceChunks.empty(); }

  // Flags in the absolute @feat.00 symbol if it is present. These usually
  // indicate if an object was compiled with certain security features enabled
  // like stack guard, safeseh, /guard:cf, or other things.
  uint32_t feat00Flags = 0;

  // True if this object file is compatible with SEH.  COFF-specific and
  // x86-only. COFF spec 5.10.1. The .sxdata section.
  bool hasSafeSEH() { return feat00Flags & 0x1; }

  // True if this file was compiled with /guard:cf.
  bool hasGuardCF() { return feat00Flags & 0x800; }

  // True if this file was compiled with /guard:ehcont.
  bool hasGuardEHCont() { return feat00Flags & 0x4000; }

  // Pointer to the PDB module descriptor builder. Various debug info records
  // will reference object files by "module index", which is here. Things like
  // source files and section contributions are also recorded here. Will be null
  // if we are not producing a PDB.
  llvm::pdb::DbiModuleDescriptorBuilder *moduleDBI = nullptr;

  const coff_section *addrsigSec = nullptr;

  const coff_section *callgraphSec = nullptr;

  // When using Microsoft precompiled headers, this is the PCH's key.
  // The same key is used by both the precompiled object, and objects using the
  // precompiled object. Any difference indicates out-of-date objects.
  std::optional<uint32_t> pchSignature;

  // Whether this file was compiled with /hotpatch.
  bool hotPatchable = false;

  // Whether the object was already merged into the final PDB.
  bool mergedIntoPDB = false;

  // If the OBJ has a .debug$T stream, this tells how it will be handled.
  TpiSource *debugTypesObj = nullptr;

  // The .debug$P or .debug$T section data if present. Empty otherwise.
  ArrayRef<uint8_t> debugTypes;

  std::optional<std::pair<StringRef, uint32_t>>
  getVariableLocation(StringRef var);

  std::optional<llvm::DILineInfo> getDILineInfo(uint32_t offset,
                                                uint32_t sectionIndex);

private:
  const coff_section* getSection(uint32_t i);
  const coff_section *getSection(COFFSymbolRef sym) {
    return getSection(sym.getSectionNumber());
  }

  void enqueuePdbFile(StringRef path, ObjFile *fromFile);

  void initializeChunks();
  void initializeSymbols();
  void initializeFlags();
  void initializeDependencies();
  void initializeECThunks();

  SectionChunk *
  readSection(uint32_t sectionNumber,
              const llvm::object::coff_aux_section_definition *def,
              StringRef leaderName);

  void readAssociativeDefinition(
      COFFSymbolRef coffSym,
      const llvm::object::coff_aux_section_definition *def);

  void readAssociativeDefinition(
      COFFSymbolRef coffSym,
      const llvm::object::coff_aux_section_definition *def,
      uint32_t parentSection);

  void recordPrevailingSymbolForMingw(
      COFFSymbolRef coffSym,
      llvm::DenseMap<StringRef, uint32_t> &prevailingSectionMap);

  void maybeAssociateSEHForMingw(
      COFFSymbolRef sym, const llvm::object::coff_aux_section_definition *def,
      const llvm::DenseMap<StringRef, uint32_t> &prevailingSectionMap);

  // Given a new symbol Sym with comdat selection Selection, if the new
  // symbol is not (yet) Prevailing and the existing comdat leader set to
  // Leader, emits a diagnostic if the new symbol and its selection doesn't
  // match the existing symbol and its selection. If either old or new
  // symbol have selection IMAGE_COMDAT_SELECT_LARGEST, Sym might replace
  // the existing leader. In that case, Prevailing is set to true.
  void
  handleComdatSelection(COFFSymbolRef sym, llvm::COFF::COMDATType &selection,
                        bool &prevailing, DefinedRegular *leader,
                        const llvm::object::coff_aux_section_definition *def);

  std::optional<Symbol *>
  createDefined(COFFSymbolRef sym,
                std::vector<const llvm::object::coff_aux_section_definition *>
                    &comdatDefs,
                bool &prevailingComdat);
  Symbol *createRegular(COFFSymbolRef sym);
  Symbol *createUndefined(COFFSymbolRef sym, bool overrideLazy);

  std::unique_ptr<COFFObjectFile> coffObj;

  // List of all chunks defined by this file. This includes both section
  // chunks and non-section chunks for common symbols.
  std::vector<Chunk *> chunks;

  std::vector<SectionChunk *> resourceChunks;

  // CodeView debug info sections.
  std::vector<SectionChunk *> debugChunks;

  // Chunks containing symbol table indices of exception handlers. Only used for
  // 32-bit x86.
  std::vector<SectionChunk *> sxDataChunks;

  // Chunks containing symbol table indices of address taken symbols, address
  // taken IAT entries, longjmp and ehcont targets. These are not linked into
  // the final binary when /guard:cf is set.
  std::vector<SectionChunk *> guardFidChunks;
  std::vector<SectionChunk *> guardIATChunks;
  std::vector<SectionChunk *> guardLJmpChunks;
  std::vector<SectionChunk *> guardEHContChunks;

  std::vector<SectionChunk *> hybmpChunks;

  // This vector contains a list of all symbols defined or referenced by this
  // file. They are indexed such that you can get a Symbol by symbol
  // index. Nonexistent indices (which are occupied by auxiliary
  // symbols in the real symbol table) are filled with null pointers.
  std::vector<Symbol *> symbols;

  // This vector contains the same chunks as Chunks, but they are
  // indexed such that you can get a SectionChunk by section index.
  // Nonexistent section indices are filled with null pointers.
  // (Because section number is 1-based, the first slot is always a
  // null pointer.) This vector is only valid during initialization.
  std::vector<SectionChunk *> sparseChunks;

  DWARFCache *dwarf = nullptr;
};

// This is a PDB type server dependency, that is not a input file per se, but
// needs to be treated like one. Such files are discovered from the debug type
// stream.
class PDBInputFile : public InputFile {
public:
  explicit PDBInputFile(COFFLinkerContext &ctx, MemoryBufferRef m);
  ~PDBInputFile();
  static bool classof(const InputFile *f) { return f->kind() == PDBKind; }
  void parse() override;

  static PDBInputFile *findFromRecordPath(const COFFLinkerContext &ctx,
                                          StringRef path, ObjFile *fromFile);

  // Record possible errors while opening the PDB file
  std::optional<std::string> loadErrorStr;

  // This is the actual interface to the PDB (if it was opened successfully)
  std::unique_ptr<llvm::pdb::NativeSession> session;

  // If the PDB has a .debug$T stream, this tells how it will be handled.
  TpiSource *debugTypesObj = nullptr;
};

// This type represents import library members that contain DLL names
// and symbols exported from the DLLs. See Microsoft PE/COFF spec. 7
// for details about the format.
class ImportFile : public InputFile {
public:
  explicit ImportFile(COFFLinkerContext &ctx, MemoryBufferRef m);

  static bool classof(const InputFile *f) { return f->kind() == ImportKind; }
  MachineTypes getMachineType() const override { return getMachineType(mb); }
  static MachineTypes getMachineType(MemoryBufferRef m);
  bool isSameImport(const ImportFile *other) const;
  bool isEC() const { return impECSym != nullptr; }

  DefinedImportData *impSym = nullptr;
  Defined *thunkSym = nullptr;
  ImportThunkChunkARM64EC *impchkThunk = nullptr;
  ImportFile *hybridFile = nullptr;
  std::string dllName;

private:
  void parse() override;
  ImportThunkChunk *makeImportThunk();

public:
  StringRef externalName;
  const coff_import_header *hdr;
  Chunk *location = nullptr;

  // Auxiliary IAT symbols and chunks on ARM64EC.
  DefinedImportData *impECSym = nullptr;
  Chunk *auxLocation = nullptr;
  Defined *auxThunkSym = nullptr;
  DefinedImportData *auxImpCopySym = nullptr;
  Chunk *auxCopyLocation = nullptr;

  // We want to eliminate dllimported symbols if no one actually refers to them.
  // These "Live" bits are used to keep track of which import library members
  // are actually in use.
  //
  // If the Live bit is turned off by MarkLive, Writer will ignore dllimported
  // symbols provided by this import library member.
  bool live;
};

// <COFF_LARGE_EXPORTS>

// This type represents Large Import definition that maps to a specific symbol name
// without an ordinal, and with an optional file association
// DLL association is only used to speed up the symbol lookups, but is used as a hint rather than a rule,
// compared to traditional PE import/export tables.
class LargeImportData {
public:
  enum LargeImportDataKind {
    LargeImportFileKind,
    SyntheticLargeImportDataKind,
  };
  explicit LargeImportData(LargeImportDataKind dataKind) : dataKind(dataKind) {}

  LargeImportDataKind largeImportDataKind() const { return dataKind; }
  bool isEC() const { return impECSym != nullptr; }

  virtual MachineTypes getMachineType() const = 0;
  virtual SymbolTable &getSymbtab() const = 0;
  virtual InputFile *getFile() { return nullptr; }
  virtual bool isLive() const { return true; }
  virtual void markLive() {}
protected:
  void createImportSymbols();
private:
  ImportThunkChunk *makeImportThunk();

  // Kind of this large import data
  LargeImportDataKind dataKind;
public:
  // Internal name of the symbol, without the __imp_ prefix appended
  StringRef internalName;
  // External name of the symbol, e.g. the name of the export in the DLL
  StringRef externalName;
  // Type of this import
  uint8_t importType{};
  // Flags set on this import
  uint8_t importFlags{};
  // Name of the DLL/PE file that this symbol comes from. Empty means a wildcard import, e.g. look up this import in all loaded DLLs
  StringRef dllName;
  // If this import is considered live, and is included into the large import section, this will be a chunk that contains the value of this data symbol
  Chunk *location = nullptr;
  // Auxiliary IAT symbol chunk for ARM64EC
  Chunk *auxLocation = nullptr;

  // Import symbol for data members and function pointers
  DefinedLargeImport *impSym = nullptr;
  // Auxiliary IAT symbol for ARM64EC
  DefinedLargeImport *impECSym = nullptr;
  // Import symbol for function thunks for code that is unaware of the fact that the member is imported and not defined locally
  Defined *thunkSym = nullptr;
  // Auxiliary IAT function thunk for ARM64EC
  Defined *auxThunkSym = nullptr;
  // Fallback thunk if auxiliary IAT slot for this import is not populated by the loader. Will enter X64 emulator and call into X64 code in the main IAT slot
  ImportThunkChunkARM64EC *impchkThunk = nullptr;
};

// Large Import Data that has been parsed from the Short Large Import Object File
class LargeImportFile : public InputFile, public LargeImportData {
public:
  explicit LargeImportFile(COFFLinkerContext &ctx, MemoryBufferRef m);

  static bool classof(const InputFile *f) { return f->kind() == LargeImportKind; }
  static bool classof(const LargeImportData *d) { return d->largeImportDataKind() == LargeImportFileKind; }

  static MachineTypes getMachineType(MemoryBufferRef m);
  MachineTypes getMachineType() const override { return getMachineType(mb); }
  SymbolTable &getSymbtab() const override { return symtab; }
  InputFile *getFile() override { return this; }
  bool isLive() const override { return live; }
  void markLive() override { live = true; }
private:
  void parse() override;

  // True if this file has been referenced by any symbols. This is set by MarkWrite
  // to eliminate large imports that are not actually referenced, which is important since large imports
  // usually imply an extremely large number of exports that would take a lot of time to dynamically link
  bool live{};
};

// Synthetic large import data created when using auto imports
class SyntheticLargeImportData : public LargeImportData {
public:
  explicit SyntheticLargeImportData(SymbolTable &symtab, StringRef externalName);

  static bool classof(const LargeImportData *d) { return d->largeImportDataKind() == SyntheticLargeImportDataKind; }
  MachineTypes getMachineType() const override;
  SymbolTable &getSymbtab() const override { return symtab; }
private:
  SymbolTable &symtab;
};
// </COFF_LARGE_EXPORTS>

// Used for LTO.
class BitcodeFile : public InputFile {
public:
  explicit BitcodeFile(SymbolTable &symtab, MemoryBufferRef mb,
                       std::unique_ptr<llvm::lto::InputFile> &obj, bool lazy);
  ~BitcodeFile();

  static BitcodeFile *create(COFFLinkerContext &ctx, MemoryBufferRef mb,
                             StringRef archiveName, uint64_t offsetInArchive,
                             bool lazy);
  static bool classof(const InputFile *f) { return f->kind() == BitcodeKind; }
  ArrayRef<Symbol *> getSymbols() { return symbols; }
  MachineTypes getMachineType() const override {
    return getMachineType(obj.get());
  }
  static MachineTypes getMachineType(const llvm::lto::InputFile *obj);
  void parseLazy();
  std::unique_ptr<llvm::lto::InputFile> obj;

private:
  void parse() override;

  std::vector<Symbol *> symbols;
};

// .dll file. MinGW only.
class DLLFile : public InputFile {
public:
  explicit DLLFile(SymbolTable &symtab, MemoryBufferRef m)
      : InputFile(symtab, DLLKind, m) {}
  static bool classof(const InputFile *f) { return f->kind() == DLLKind; }
  void parse() override;
  MachineTypes getMachineType() const override;

  struct Symbol {
    StringRef dllName;
    StringRef symbolName;
    llvm::COFF::ImportNameType nameType;
    llvm::COFF::ImportType importType;
  };

  void makeImport(Symbol *s);

private:
  std::unique_ptr<COFFObjectFile> coffObj;
  llvm::StringSet<> seen;
};

inline bool isBitcode(MemoryBufferRef mb) {
  return identify_magic(mb.getBuffer()) == llvm::file_magic::bitcode;
}

std::string replaceThinLTOSuffix(StringRef path, StringRef suffix,
                                 StringRef repl);
} // namespace coff

std::string toString(const coff::InputFile *file);
} // namespace lld

#endif
