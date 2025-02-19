//===- DLL.cpp ------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines various types of chunks for the DLL import or export
// descriptor tables. They are inherently Windows-specific.
// You need to read Microsoft PE/COFF spec to understand details
// about the data structures.
//
// If you are not particularly interested in linking against Windows
// DLL, you can skip this file, and you should still be able to
// understand the rest of the linker.
//
//===----------------------------------------------------------------------===//

#include "DLL.h"
#include "COFFLinkerContext.h"
#include "Chunks.h"
#include "SymbolTable.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Path.h"
// <COFF_LARGE_EXPORTS>
#include "CityHash.h"
#include "llvm/Object/COFFLargeImport.h"
// <COFF_LARGE_EXPORTS>

using namespace llvm;
using namespace llvm::object;
using namespace llvm::support::endian;
using namespace llvm::COFF;

namespace lld::coff {
namespace {

// Import table

// A chunk for the import descriptor table.
class HintNameChunk : public NonSectionChunk {
public:
  HintNameChunk(StringRef n, uint16_t h) : name(n), hint(h) {}

  size_t getSize() const override {
    // Starts with 2 byte Hint field, followed by a null-terminated string,
    // ends with 0 or 1 byte padding.
    return alignTo(name.size() + 3, 2);
  }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());
    write16le(buf, hint);
    memcpy(buf + 2, name.data(), name.size());
  }

private:
  StringRef name;
  uint16_t hint;
};

// A chunk for the import descriptor table.
class LookupChunk : public NonSectionChunk {
public:
  explicit LookupChunk(COFFLinkerContext &ctx, Chunk *c)
      : hintName(c), ctx(ctx) {
    setAlignment(ctx.config.wordsize);
  }
  size_t getSize() const override { return ctx.config.wordsize; }

  void writeTo(uint8_t *buf) const override {
    if (ctx.config.is64())
      write64le(buf, hintName->getRVA());
    else
      write32le(buf, hintName->getRVA());
  }

  Chunk *hintName;

private:
  COFFLinkerContext &ctx;
};

// A chunk for the import descriptor table.
// This chunk represent import-by-ordinal symbols.
// See Microsoft PE/COFF spec 7.1. Import Header for details.
class OrdinalOnlyChunk : public NonSectionChunk {
public:
  explicit OrdinalOnlyChunk(COFFLinkerContext &c, uint16_t v)
      : ordinal(v), ctx(c) {
    setAlignment(ctx.config.wordsize);
  }
  size_t getSize() const override { return ctx.config.wordsize; }

  void writeTo(uint8_t *buf) const override {
    // An import-by-ordinal slot has MSB 1 to indicate that
    // this is import-by-ordinal (and not import-by-name).
    if (ctx.config.is64()) {
      write64le(buf, (1ULL << 63) | ordinal);
    } else {
      write32le(buf, (1ULL << 31) | ordinal);
    }
  }

  uint16_t ordinal;

private:
  COFFLinkerContext &ctx;
};

// A chunk for the import descriptor table.
class ImportDirectoryChunk : public NonSectionChunk {
public:
  explicit ImportDirectoryChunk(Chunk *n) : dllName(n) { setAlignment(4); }
  size_t getSize() const override { return sizeof(ImportDirectoryTableEntry); }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());

    auto *e = (coff_import_directory_table_entry *)(buf);
    e->ImportLookupTableRVA = lookupTab->getRVA();
    e->NameRVA = dllName->getRVA();
    e->ImportAddressTableRVA = addressTab->getRVA();
  }

  Chunk *dllName;
  Chunk *lookupTab;
  Chunk *addressTab;
};

// A chunk representing null terminator in the import table.
// Contents of this chunk is always null bytes.
class NullChunk : public NonSectionChunk {
public:
  explicit NullChunk(size_t n) : size(n) { hasData = false; }
  size_t getSize() const override { return size; }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, size);
  }

private:
  size_t size;
};

// A chunk for ARM64EC auxiliary IAT.
class AuxImportChunk : public NonSectionChunk {
public:
  explicit AuxImportChunk(ImportFile *file) : file(file) {
    setAlignment(sizeof(uint64_t));
  }
  size_t getSize() const override { return sizeof(uint64_t); }

  void writeTo(uint8_t *buf) const override {
    uint64_t impchkVA = 0;
    if (file->impchkThunk)
      impchkVA = file->impchkThunk->getRVA() + file->ctx.config.imageBase;
    write64le(buf, impchkVA);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    if (file->impchkThunk)
      res->emplace_back(rva, file->ctx.config.machine);
  }

private:
  ImportFile *file;
};

static std::vector<std::vector<DefinedImportData *>>
binImports(COFFLinkerContext &ctx,
           const std::vector<DefinedImportData *> &imports) {
  // Group DLL-imported symbols by DLL name because that's how
  // symbols are laid out in the import descriptor table.
  auto less = [&ctx](const std::string &a, const std::string &b) {
    return ctx.config.dllOrder[a] < ctx.config.dllOrder[b];
  };
  std::map<std::string, std::vector<DefinedImportData *>, decltype(less)> m(
      less);
  for (DefinedImportData *sym : imports)
    m[sym->getDLLName().lower()].push_back(sym);

  std::vector<std::vector<DefinedImportData *>> v;
  for (auto &kv : m) {
    // Sort symbols by name for each group.
    std::vector<DefinedImportData *> &syms = kv.second;
    llvm::sort(syms, [](DefinedImportData *a, DefinedImportData *b) {
      auto getBaseName = [](DefinedImportData *sym) {
        StringRef name = sym->getName();
        name.consume_front("__imp_");
        // Skip aux_ part of ARM64EC function symbol name.
        if (sym->file->impchkThunk)
          name.consume_front("aux_");
        return name;
      };
      return getBaseName(a) < getBaseName(b);
    });
    v.push_back(std::move(syms));
  }
  return v;
}

// See Microsoft PE/COFF spec 4.3 for details.

// A chunk for the delay import descriptor table etnry.
class DelayDirectoryChunk : public NonSectionChunk {
public:
  explicit DelayDirectoryChunk(Chunk *n) : dllName(n) { setAlignment(4); }

  size_t getSize() const override {
    return sizeof(delay_import_directory_table_entry);
  }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());

    auto *e = (delay_import_directory_table_entry *)(buf);
    e->Attributes = 1;
    e->Name = dllName->getRVA();
    e->ModuleHandle = moduleHandle->getRVA();
    e->DelayImportAddressTable = addressTab->getRVA();
    e->DelayImportNameTable = nameTab->getRVA();
  }

  Chunk *dllName;
  Chunk *moduleHandle;
  Chunk *addressTab;
  Chunk *nameTab;
};

// Initial contents for delay-loaded functions.
// This code calls __delayLoadHelper2 function to resolve a symbol
// which then overwrites its jump table slot with the result
// for subsequent function calls.
static const uint8_t thunkX64[] = {
    0x48, 0x8D, 0x05, 0, 0, 0, 0,       // lea     rax, [__imp_<FUNCNAME>]
    0xE9, 0, 0, 0, 0,                   // jmp     __tailMerge_<lib>
};

static const uint8_t tailMergeX64[] = {
    0x51,                               // push    rcx
    0x52,                               // push    rdx
    0x41, 0x50,                         // push    r8
    0x41, 0x51,                         // push    r9
    0x48, 0x83, 0xEC, 0x48,             // sub     rsp, 48h
    0x66, 0x0F, 0x7F, 0x04, 0x24,       // movdqa  xmmword ptr [rsp], xmm0
    0x66, 0x0F, 0x7F, 0x4C, 0x24, 0x10, // movdqa  xmmword ptr [rsp+10h], xmm1
    0x66, 0x0F, 0x7F, 0x54, 0x24, 0x20, // movdqa  xmmword ptr [rsp+20h], xmm2
    0x66, 0x0F, 0x7F, 0x5C, 0x24, 0x30, // movdqa  xmmword ptr [rsp+30h], xmm3
    0x48, 0x8B, 0xD0,                   // mov     rdx, rax
    0x48, 0x8D, 0x0D, 0, 0, 0, 0,       // lea     rcx, [___DELAY_IMPORT_...]
    0xE8, 0, 0, 0, 0,                   // call    __delayLoadHelper2
    0x66, 0x0F, 0x6F, 0x04, 0x24,       // movdqa  xmm0, xmmword ptr [rsp]
    0x66, 0x0F, 0x6F, 0x4C, 0x24, 0x10, // movdqa  xmm1, xmmword ptr [rsp+10h]
    0x66, 0x0F, 0x6F, 0x54, 0x24, 0x20, // movdqa  xmm2, xmmword ptr [rsp+20h]
    0x66, 0x0F, 0x6F, 0x5C, 0x24, 0x30, // movdqa  xmm3, xmmword ptr [rsp+30h]
    0x48, 0x83, 0xC4, 0x48,             // add     rsp, 48h
    0x41, 0x59,                         // pop     r9
    0x41, 0x58,                         // pop     r8
    0x5A,                               // pop     rdx
    0x59,                               // pop     rcx
    0xFF, 0xE0,                         // jmp     rax
};

static const uint8_t tailMergeUnwindInfoX64[] = {
    0x01,       // Version=1, Flags=UNW_FLAG_NHANDLER
    0x0a,       // Size of prolog
    0x05,       // Count of unwind codes
    0x00,       // No frame register
    0x0a, 0x82, // Offset 0xa: UWOP_ALLOC_SMALL(0x48)
    0x06, 0x02, // Offset 6: UWOP_ALLOC_SMALL(8)
    0x04, 0x02, // Offset 4: UWOP_ALLOC_SMALL(8)
    0x02, 0x02, // Offset 2: UWOP_ALLOC_SMALL(8)
    0x01, 0x02, // Offset 1: UWOP_ALLOC_SMALL(8)
    0x00, 0x00  // Padding to align on 32-bits
};

static const uint8_t thunkX86[] = {
    0xB8, 0, 0, 0, 0,  // mov   eax, offset ___imp__<FUNCNAME>
    0xE9, 0, 0, 0, 0,  // jmp   __tailMerge_<lib>
};

static const uint8_t tailMergeX86[] = {
    0x51,              // push  ecx
    0x52,              // push  edx
    0x50,              // push  eax
    0x68, 0, 0, 0, 0,  // push  offset ___DELAY_IMPORT_DESCRIPTOR_<DLLNAME>_dll
    0xE8, 0, 0, 0, 0,  // call  ___delayLoadHelper2@8
    0x5A,              // pop   edx
    0x59,              // pop   ecx
    0xFF, 0xE0,        // jmp   eax
};

static const uint8_t thunkARM[] = {
    0x40, 0xf2, 0x00, 0x0c, // mov.w   ip, #0 __imp_<FUNCNAME>
    0xc0, 0xf2, 0x00, 0x0c, // mov.t   ip, #0 __imp_<FUNCNAME>
    0x00, 0xf0, 0x00, 0xb8, // b.w     __tailMerge_<lib>
};

static const uint8_t tailMergeARM[] = {
    0x2d, 0xe9, 0x0f, 0x48, // push.w  {r0, r1, r2, r3, r11, lr}
    0x0d, 0xf2, 0x10, 0x0b, // addw    r11, sp, #16
    0x2d, 0xed, 0x10, 0x0b, // vpush   {d0, d1, d2, d3, d4, d5, d6, d7}
    0x61, 0x46,             // mov     r1, ip
    0x40, 0xf2, 0x00, 0x00, // mov.w   r0, #0 DELAY_IMPORT_DESCRIPTOR
    0xc0, 0xf2, 0x00, 0x00, // mov.t   r0, #0 DELAY_IMPORT_DESCRIPTOR
    0x00, 0xf0, 0x00, 0xd0, // bl      #0 __delayLoadHelper2
    0x84, 0x46,             // mov     ip, r0
    0xbd, 0xec, 0x10, 0x0b, // vpop    {d0, d1, d2, d3, d4, d5, d6, d7}
    0xbd, 0xe8, 0x0f, 0x48, // pop.w   {r0, r1, r2, r3, r11, lr}
    0x60, 0x47,             // bx      ip
};

static const uint8_t thunkARM64[] = {
    0x11, 0x00, 0x00, 0x90, // adrp    x17, #0      __imp_<FUNCNAME>
    0x31, 0x02, 0x00, 0x91, // add     x17, x17, #0 :lo12:__imp_<FUNCNAME>
    0x00, 0x00, 0x00, 0x14, // b       __tailMerge_<lib>
};

static const uint8_t tailMergeARM64[] = {
    0xfd, 0x7b, 0xb3, 0xa9, // stp     x29, x30, [sp, #-208]!
    0xfd, 0x03, 0x00, 0x91, // mov     x29, sp
    0xe0, 0x07, 0x01, 0xa9, // stp     x0, x1, [sp, #16]
    0xe2, 0x0f, 0x02, 0xa9, // stp     x2, x3, [sp, #32]
    0xe4, 0x17, 0x03, 0xa9, // stp     x4, x5, [sp, #48]
    0xe6, 0x1f, 0x04, 0xa9, // stp     x6, x7, [sp, #64]
    0xe0, 0x87, 0x02, 0xad, // stp     q0, q1, [sp, #80]
    0xe2, 0x8f, 0x03, 0xad, // stp     q2, q3, [sp, #112]
    0xe4, 0x97, 0x04, 0xad, // stp     q4, q5, [sp, #144]
    0xe6, 0x9f, 0x05, 0xad, // stp     q6, q7, [sp, #176]
    0xe1, 0x03, 0x11, 0xaa, // mov     x1, x17
    0x00, 0x00, 0x00, 0x90, // adrp    x0, #0     DELAY_IMPORT_DESCRIPTOR
    0x00, 0x00, 0x00, 0x91, // add     x0, x0, #0 :lo12:DELAY_IMPORT_DESCRIPTOR
    0x00, 0x00, 0x00, 0x94, // bl      #0 __delayLoadHelper2
    0xf0, 0x03, 0x00, 0xaa, // mov     x16, x0
    0xe6, 0x9f, 0x45, 0xad, // ldp     q6, q7, [sp, #176]
    0xe4, 0x97, 0x44, 0xad, // ldp     q4, q5, [sp, #144]
    0xe2, 0x8f, 0x43, 0xad, // ldp     q2, q3, [sp, #112]
    0xe0, 0x87, 0x42, 0xad, // ldp     q0, q1, [sp, #80]
    0xe6, 0x1f, 0x44, 0xa9, // ldp     x6, x7, [sp, #64]
    0xe4, 0x17, 0x43, 0xa9, // ldp     x4, x5, [sp, #48]
    0xe2, 0x0f, 0x42, 0xa9, // ldp     x2, x3, [sp, #32]
    0xe0, 0x07, 0x41, 0xa9, // ldp     x0, x1, [sp, #16]
    0xfd, 0x7b, 0xcd, 0xa8, // ldp     x29, x30, [sp], #208
    0x00, 0x02, 0x1f, 0xd6, // br      x16
};

// A chunk for the delay import thunk.
class ThunkChunkX64 : public NonSectionCodeChunk {
public:
  ThunkChunkX64(Defined *i, Chunk *tm) : imp(i), tailMerge(tm) {}

  size_t getSize() const override { return sizeof(thunkX64); }
  MachineTypes getMachine() const override { return AMD64; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkX64, sizeof(thunkX64));
    write32le(buf + 3, imp->getRVA() - rva - 7);
    write32le(buf + 8, tailMerge->getRVA() - rva - 12);
  }

  Defined *imp = nullptr;
  Chunk *tailMerge = nullptr;
};

class TailMergeChunkX64 : public NonSectionCodeChunk {
public:
  TailMergeChunkX64(Chunk *d, Defined *h) : desc(d), helper(h) {}

  size_t getSize() const override { return sizeof(tailMergeX64); }
  MachineTypes getMachine() const override { return AMD64; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeX64, sizeof(tailMergeX64));
    write32le(buf + 39, desc->getRVA() - rva - 43);
    write32le(buf + 44, helper->getRVA() - rva - 48);
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;
};

class TailMergePDataChunkX64 : public NonSectionChunk {
public:
  TailMergePDataChunkX64(Chunk *tm, Chunk *unwind) : tm(tm), unwind(unwind) {
    // See
    // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function
    setAlignment(4);
  }

  size_t getSize() const override { return 3 * sizeof(uint32_t); }

  void writeTo(uint8_t *buf) const override {
    write32le(buf + 0, tm->getRVA()); // TailMergeChunk start RVA
    write32le(buf + 4, tm->getRVA() + tm->getSize()); // TailMergeChunk stop RVA
    write32le(buf + 8, unwind->getRVA());             // UnwindInfo RVA
  }

  Chunk *tm = nullptr;
  Chunk *unwind = nullptr;
};

class TailMergeUnwindInfoX64 : public NonSectionChunk {
public:
  TailMergeUnwindInfoX64() {
    // See
    // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_info
    setAlignment(4);
  }

  size_t getSize() const override { return sizeof(tailMergeUnwindInfoX64); }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeUnwindInfoX64, sizeof(tailMergeUnwindInfoX64));
  }
};

class ThunkChunkX86 : public NonSectionCodeChunk {
public:
  ThunkChunkX86(COFFLinkerContext &ctx, Defined *i, Chunk *tm)
      : imp(i), tailMerge(tm), ctx(ctx) {}

  size_t getSize() const override { return sizeof(thunkX86); }
  MachineTypes getMachine() const override { return I386; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkX86, sizeof(thunkX86));
    write32le(buf + 1, imp->getRVA() + ctx.config.imageBase);
    write32le(buf + 6, tailMerge->getRVA() - rva - 10);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva + 1, ctx.config.machine);
  }

  Defined *imp = nullptr;
  Chunk *tailMerge = nullptr;

private:
  const COFFLinkerContext &ctx;
};

class TailMergeChunkX86 : public NonSectionCodeChunk {
public:
  TailMergeChunkX86(COFFLinkerContext &ctx, Chunk *d, Defined *h)
      : desc(d), helper(h), ctx(ctx) {}

  size_t getSize() const override { return sizeof(tailMergeX86); }
  MachineTypes getMachine() const override { return I386; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeX86, sizeof(tailMergeX86));
    write32le(buf + 4, desc->getRVA() + ctx.config.imageBase);
    write32le(buf + 9, helper->getRVA() - rva - 13);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva + 4, ctx.config.machine);
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;

private:
  const COFFLinkerContext &ctx;
};

class ThunkChunkARM : public NonSectionCodeChunk {
public:
  ThunkChunkARM(COFFLinkerContext &ctx, Defined *i, Chunk *tm)
      : imp(i), tailMerge(tm), ctx(ctx) {
    setAlignment(2);
  }

  size_t getSize() const override { return sizeof(thunkARM); }
  MachineTypes getMachine() const override { return ARMNT; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkARM, sizeof(thunkARM));
    applyMOV32T(buf + 0, imp->getRVA() + ctx.config.imageBase);
    applyBranch24T(buf + 8, tailMerge->getRVA() - rva - 12);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva + 0, IMAGE_REL_BASED_ARM_MOV32T);
  }

  Defined *imp = nullptr;
  Chunk *tailMerge = nullptr;

private:
  const COFFLinkerContext &ctx;
};

class TailMergeChunkARM : public NonSectionCodeChunk {
public:
  TailMergeChunkARM(COFFLinkerContext &ctx, Chunk *d, Defined *h)
      : desc(d), helper(h), ctx(ctx) {
    setAlignment(2);
  }

  size_t getSize() const override { return sizeof(tailMergeARM); }
  MachineTypes getMachine() const override { return ARMNT; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeARM, sizeof(tailMergeARM));
    applyMOV32T(buf + 14, desc->getRVA() + ctx.config.imageBase);
    applyBranch24T(buf + 22, helper->getRVA() - rva - 26);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva + 14, IMAGE_REL_BASED_ARM_MOV32T);
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;

private:
  const COFFLinkerContext &ctx;
};

class ThunkChunkARM64 : public NonSectionCodeChunk {
public:
  ThunkChunkARM64(Defined *i, Chunk *tm) : imp(i), tailMerge(tm) {
    setAlignment(4);
  }

  size_t getSize() const override { return sizeof(thunkARM64); }
  MachineTypes getMachine() const override { return ARM64; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkARM64, sizeof(thunkARM64));
    applyArm64Addr(buf + 0, imp->getRVA(), rva + 0, 12);
    applyArm64Imm(buf + 4, imp->getRVA() & 0xfff, 0);
    applyArm64Branch26(buf + 8, tailMerge->getRVA() - rva - 8);
  }

  Defined *imp = nullptr;
  Chunk *tailMerge = nullptr;
};

class TailMergeChunkARM64 : public NonSectionCodeChunk {
public:
  TailMergeChunkARM64(Chunk *d, Defined *h) : desc(d), helper(h) {
    setAlignment(4);
  }

  size_t getSize() const override { return sizeof(tailMergeARM64); }
  MachineTypes getMachine() const override { return ARM64; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeARM64, sizeof(tailMergeARM64));
    applyArm64Addr(buf + 44, desc->getRVA(), rva + 44, 12);
    applyArm64Imm(buf + 48, desc->getRVA() & 0xfff, 0);
    applyArm64Branch26(buf + 52, helper->getRVA() - rva - 52);
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;
};

// A chunk for the import descriptor table.
class DelayAddressChunk : public NonSectionChunk {
public:
  explicit DelayAddressChunk(COFFLinkerContext &ctx, Chunk *c)
      : thunk(c), ctx(ctx) {
    setAlignment(ctx.config.wordsize);
  }
  size_t getSize() const override { return ctx.config.wordsize; }

  void writeTo(uint8_t *buf) const override {
    if (ctx.config.is64()) {
      write64le(buf, thunk->getRVA() + ctx.config.imageBase);
    } else {
      uint32_t bit = 0;
      // Pointer to thumb code must have the LSB set, so adjust it.
      if (ctx.config.machine == ARMNT)
        bit = 1;
      write32le(buf, (thunk->getRVA() + ctx.config.imageBase) | bit);
    }
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva, ctx.config.machine);
  }

  Chunk *thunk;

private:
  const COFFLinkerContext &ctx;
};

// Export table
// Read Microsoft PE/COFF spec 5.3 for details.

// A chunk for the export descriptor table.
class ExportDirectoryChunk : public NonSectionChunk {
public:
  ExportDirectoryChunk(int baseOrdinal, int maxOrdinal, int nameTabSize,
                       Chunk *d, Chunk *a, Chunk *n, Chunk *o)
      : baseOrdinal(baseOrdinal), maxOrdinal(maxOrdinal),
        nameTabSize(nameTabSize), dllName(d), addressTab(a), nameTab(n),
        ordinalTab(o) {}

  size_t getSize() const override {
    return sizeof(export_directory_table_entry);
  }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());

    auto *e = (export_directory_table_entry *)(buf);
    e->NameRVA = dllName->getRVA();
    e->OrdinalBase = baseOrdinal;
    e->AddressTableEntries = (maxOrdinal - baseOrdinal) + 1;
    e->NumberOfNamePointers = nameTabSize;
    e->ExportAddressTableRVA = addressTab->getRVA();
    e->NamePointerRVA = nameTab->getRVA();
    e->OrdinalTableRVA = ordinalTab->getRVA();
  }

  uint16_t baseOrdinal;
  uint16_t maxOrdinal;
  uint16_t nameTabSize;
  Chunk *dllName;
  Chunk *addressTab;
  Chunk *nameTab;
  Chunk *ordinalTab;
};

class AddressTableChunk : public NonSectionChunk {
public:
  explicit AddressTableChunk(COFFLinkerContext &ctx, size_t baseOrdinal,
                             size_t maxOrdinal)
      : baseOrdinal(baseOrdinal), size((maxOrdinal - baseOrdinal) + 1),
        ctx(ctx) {}
  size_t getSize() const override { return size * 4; }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());

    for (const Export &e : ctx.config.exports) {
      assert(e.ordinal >= baseOrdinal && "Export symbol has invalid ordinal");
      // Subtract the OrdinalBase to get the index.
      uint8_t *p = buf + (e.ordinal - baseOrdinal) * 4;
      uint32_t bit = 0;
      // Pointer to thumb code must have the LSB set, so adjust it.
      if (ctx.config.machine == ARMNT && !e.data)
        bit = 1;
      if (e.forwardChunk) {
        write32le(p, e.forwardChunk->getRVA() | bit);
      } else {
        assert(cast<Defined>(e.sym)->getRVA() != 0 &&
               "Exported symbol unmapped");
        write32le(p, cast<Defined>(e.sym)->getRVA() | bit);
      }
    }
  }

private:
  size_t baseOrdinal;
  size_t size;
  const COFFLinkerContext &ctx;
};

class NamePointersChunk : public NonSectionChunk {
public:
  explicit NamePointersChunk(std::vector<Chunk *> &v) : chunks(v) {}
  size_t getSize() const override { return chunks.size() * 4; }

  void writeTo(uint8_t *buf) const override {
    for (Chunk *c : chunks) {
      write32le(buf, c->getRVA());
      buf += 4;
    }
  }

private:
  std::vector<Chunk *> chunks;
};

class ExportOrdinalChunk : public NonSectionChunk {
public:
  explicit ExportOrdinalChunk(const COFFLinkerContext &ctx, size_t baseOrdinal,
                              size_t tableSize)
      : baseOrdinal(baseOrdinal), size(tableSize), ctx(ctx) {}
  size_t getSize() const override { return size * 2; }

  void writeTo(uint8_t *buf) const override {
    for (const Export &e : ctx.config.exports) {
      if (e.noname)
        continue;
      assert(e.ordinal >= baseOrdinal && "Export symbol has invalid ordinal");
      // This table stores unbiased indices, so subtract OrdinalBase.
      write16le(buf, e.ordinal - baseOrdinal);
      buf += 2;
    }
  }

private:
  size_t baseOrdinal;
  size_t size;
  const COFFLinkerContext &ctx;
};

} // anonymous namespace

void IdataContents::create(COFFLinkerContext &ctx) {
  std::vector<std::vector<DefinedImportData *>> v = binImports(ctx, imports);

  // Create .idata contents for each DLL.
  for (std::vector<DefinedImportData *> &syms : v) {
    // Create lookup and address tables. If they have external names,
    // we need to create hintName chunks to store the names.
    // If they don't (if they are import-by-ordinals), we store only
    // ordinal values to the table.
    size_t base = lookups.size();
    for (DefinedImportData *s : syms) {
      uint16_t ord = s->getOrdinal();
      if (s->getExternalName().empty()) {
        lookups.push_back(make<OrdinalOnlyChunk>(ctx, ord));
        addresses.push_back(make<OrdinalOnlyChunk>(ctx, ord));
      } else {
        auto *c = make<HintNameChunk>(s->getExternalName(), ord);
        lookups.push_back(make<LookupChunk>(ctx, c));
        addresses.push_back(make<LookupChunk>(ctx, c));
        hints.push_back(c);
      }

      if (s->file->impECSym) {
        auto chunk = make<AuxImportChunk>(s->file);
        auxIat.push_back(chunk);
        s->file->impECSym->setLocation(chunk);

        chunk = make<AuxImportChunk>(s->file);
        auxIatCopy.push_back(chunk);
        s->file->auxImpCopySym->setLocation(chunk);
      }
    }
    // Terminate with null values.
    lookups.push_back(make<NullChunk>(ctx.config.wordsize));
    addresses.push_back(make<NullChunk>(ctx.config.wordsize));
    if (ctx.config.machine == ARM64EC) {
      auxIat.push_back(make<NullChunk>(ctx.config.wordsize));
      auxIatCopy.push_back(make<NullChunk>(ctx.config.wordsize));
    }

    for (int i = 0, e = syms.size(); i < e; ++i)
      syms[i]->setLocation(addresses[base + i]);

    // Create the import table header.
    dllNames.push_back(make<StringChunk>(syms[0]->getDLLName()));
    auto *dir = make<ImportDirectoryChunk>(dllNames.back());
    dir->lookupTab = lookups[base];
    dir->addressTab = addresses[base];
    dirs.push_back(dir);
  }
  // Add null terminator.
  dirs.push_back(make<NullChunk>(sizeof(ImportDirectoryTableEntry)));
}

// <COFF_LARGE_EXPORTS>
class LargeImportLoaderCallbackChunk : public NonSectionCodeChunk {
public:
  LargeImportLoaderCallbackChunk(Defined* callbackDataSymbol, Chunk* &sectionHeaderChunk) : callbackDataSymbol(callbackDataSymbol), sectionHeaderChunk(sectionHeaderChunk) {}
protected:
  Defined *callbackDataSymbol{};
  Chunk* &sectionHeaderChunk;
};

// This code will load the base address of the image, and address of the first import descriptor, and then call the large loader link function
static const uint8_t largeLoaderCallbackX64[] = {
  0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,       // lea  rcx, [__ImageBase]
  0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,       // lea  rdx, [.ildata]
  0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [__imp___large_loader_link]
};

class LargeImportLoaderCallbackChunkX64 : public LargeImportLoaderCallbackChunk {
public:
  LargeImportLoaderCallbackChunkX64(Defined *callbackDataSymbol, Chunk* &sectionHeaderChunk) : LargeImportLoaderCallbackChunk(callbackDataSymbol, sectionHeaderChunk) {
    // Align to the power of 16, just like import thunks
    p2Align = 4;
  }

  size_t getSize() const override {
    return sizeof(largeLoaderCallbackX64);
  }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, largeLoaderCallbackX64, sizeof(largeLoaderCallbackX64));
    write32le(buf + 3, 0 - rva - 7); // __ImageBase is at RVA 0, therefore to get it we need to negate our own RVA and also subtract the size of the current instruction (7 byte lea)
    write32le(buf + 10, sectionHeaderChunk->getRVA() - rva - 14);
    write32le(buf + 16, callbackDataSymbol->getRVA() - rva - 20);
  }
};

class AbsoluteDefinedSymbolAddressChunk : public NonSectionChunk {
public:
  AbsoluteDefinedSymbolAddressChunk(COFFLinkerContext &context, Defined* definedSymbol) : ctx(context), definedSymbol(definedSymbol) {
    p2Align = 3; // Address needs to be aligned to 8 byte boundary
  }

  size_t getSize() const override {
    // Size of the pointer is the size of this chunk
    return ctx.config.wordsize;
  }

  void writeTo(uint8_t *buf) const override {
    if (ctx.config.is64()) {
      write64le(buf, definedSymbol->getRVA() + ctx.config.imageBase);
    } else {
      uint32_t bit = 0;
      // Pointer to thumb code must have the LSB set, so adjust it if the symbols output chunk is marked as Code
      if (ctx.config.machine == ARMNT && (definedSymbol->getChunk()->getOutputCharacteristics() & IMAGE_SCN_CNT_CODE) != 0)
        bit = 1;
      write32le(buf, (definedSymbol->getRVA() + ctx.config.imageBase) | bit);
    }
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva, ctx.config.machine);
  }
protected:
  COFFLinkerContext &ctx;
  Defined *definedSymbol;
};

class LargeLoaderImportChunk final : public NonSectionChunk {
public:
  LargeLoaderImportChunk(const COFFLargeLoaderImport &import, Chunk *nameChunk) : import(import), nameChunk(nameChunk) {
    setAlignment(alignof(COFFLargeLoaderImport));
  }

  size_t getSize() const override { return sizeof(import); }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, &import, sizeof(import));
    write32le(buf + offsetof(COFFLargeLoaderImport, NameOffset), nameChunk->getRVA() - getRVA());
  }
private:
  COFFLargeLoaderImport import;
  Chunk *nameChunk;
};

class LargeLoaderImportSectionHeaderChunk final : public NonSectionChunk {
public:
  LargeLoaderImportSectionHeaderChunk(const COFFLargeLoaderImportSectionHeader &header, Chunk *addressTable, Chunk *importedExportSections, Chunk *importTable, Chunk *imageNameChunk) :
    sectionHeader(header), addressTable(addressTable), importedExportSections(importedExportSections), importTable(importTable), imageNameChunk(imageNameChunk) {
    setAlignment(alignof(COFFLargeLoaderImportSectionHeader));
  }

  size_t getSize() const override { return sizeof(sectionHeader); }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, &sectionHeader, sizeof(sectionHeader));
    write32le(buf + offsetof(COFFLargeLoaderImportSectionHeader, AddressTableOffset), addressTable->getRVA() - getRVA());
    write32le(buf + offsetof(COFFLargeLoaderImportSectionHeader, ImportedExportSectionsOffset), importedExportSections ? importedExportSections->getRVA() - getRVA() : 0);
    write32le(buf + offsetof(COFFLargeLoaderImportSectionHeader, ImportTableOffset), importTable->getRVA() - getRVA());
    write32le(buf + offsetof(COFFLargeLoaderImportSectionHeader, ImageFilenameOffset), imageNameChunk->getRVA() - getRVA());
  }
private:
  COFFLargeLoaderImportSectionHeader sectionHeader;
  Chunk *addressTable;
  Chunk *importedExportSections;
  Chunk *importTable;
  Chunk *imageNameChunk;
};

class SymbolRVAChunk final : public NonSectionChunk {
public:
  SymbolRVAChunk(COFFLinkerContext &context, Symbol *symbol) : ctx(context), symbol(symbol) {
    p2Align = 3; // Align RVAs to the 8 byte boundary
  }

  size_t getSize() const override {
    return ctx.config.wordsize;
  }

  void writeTo(uint8_t *buf) const override {
    // Symbol must always become defined when we are actually about to write it's RVA
    if (!isa<Defined>(symbol))
      fatal("Symbol was not defined while writing RVA chunk for it: " + symbol->getName());
    Defined *definedSymbol = cast<Defined>(symbol);

    if (ctx.config.is64()) {
      write64le(buf, definedSymbol->getRVA());
    } else {
      uint32_t bit = 0;
      // Pointer to thumb code must have the LSB set, so adjust it if the symbols output chunk is marked as Code
      if (ctx.config.machine == ARMNT && (definedSymbol->getChunk()->getOutputCharacteristics() & IMAGE_SCN_CNT_CODE) != 0)
        bit = 1;
      write32le(buf, definedSymbol->getRVA() | bit);
    }
  }
private:
  COFFLinkerContext &ctx;
  Symbol *symbol;
};

class LargeLoaderExportChunk final : public NonSectionChunk {
public:
  LargeLoaderExportChunk(const COFFLargeLoaderExport &largeExport, Chunk *nameChunk) : largeExport(largeExport), nameChunk(nameChunk) {
    setAlignment(alignof(COFFLargeLoaderExport));
  }

  size_t getSize() const override { return sizeof(largeExport); }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, &largeExport, sizeof(largeExport));
    write32le(buf + offsetof(COFFLargeLoaderExport, NameOffset), nameChunk->getRVA() - getRVA());
  }
private:
  COFFLargeLoaderExport largeExport;
  Chunk *nameChunk;
};

class LargeLoaderExportHashBucketChunk final : public NonSectionChunk {
public:
  explicit LargeLoaderExportHashBucketChunk(const COFFLargeLoaderExportHashBucket &hashBucket) : hashBucket(hashBucket) {
    setAlignment(alignof(COFFLargeLoaderExportHashBucket));
  }

  size_t getSize() const override { return sizeof(hashBucket); }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, &hashBucket, sizeof(hashBucket));
  }
private:
  COFFLargeLoaderExportHashBucket hashBucket;
};

class LargeLoaderExportSectionHeaderChunk final : public NonSectionChunk {
public:
  LargeLoaderExportSectionHeaderChunk(
      const COFFLargeLoaderExportSectionHeader &header, Chunk *exportRVATable,
      Chunk *exportHashBucketTable, Chunk *exportTable, Chunk *imageNameChunk)
      : sectionHeader(header), exportRVATable(exportRVATable),
        exportHashBucketTable(exportHashBucketTable), exportTable(exportTable),
        imageNameChunk(imageNameChunk) {
    setAlignment(alignof(COFFLargeLoaderExportSectionHeader));
  }

  size_t getSize() const override { return sizeof(sectionHeader); }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, &sectionHeader, sizeof(sectionHeader));
    write32le(buf + offsetof(COFFLargeLoaderExportSectionHeader,
                             ExportRVATableOffset),
              exportRVATable->getRVA() - getRVA());
    write32le(buf + offsetof(COFFLargeLoaderExportSectionHeader,
                             ExportHashBucketTableOffset),
              exportHashBucketTable->getRVA() - getRVA());
    write32le(
        buf + offsetof(COFFLargeLoaderExportSectionHeader, ExportTableOffset),
        exportTable->getRVA() - getRVA());
    write32le(
        buf + offsetof(COFFLargeLoaderExportSectionHeader, SectionHeaderRVA),
        getRVA());
    write32le(
        buf + offsetof(COFFLargeLoaderExportSectionHeader, ImageFilenameOffset),
        imageNameChunk->getRVA() - getRVA());
  }

private:
  COFFLargeLoaderExportSectionHeader sectionHeader;
  Chunk *exportRVATable;
  Chunk *exportHashBucketTable;
  Chunk *exportTable;
  Chunk *imageNameChunk;
};

void LargeIdataContents::createLoaderImports(COFFLinkerContext &ctx, int maxLoadOrder) {

  StringRef loaderLibraryName = saver().save("LargeLoader.dll");

  // Make sure the large loader DLL is loaded before any other DLLs with large
  // imports, but respect user specified load order if possible
  std::string loaderLibraryNameLowercase = loaderLibraryName.lower();
  if (ctx.config.dllOrder.count(loaderLibraryNameLowercase) == 0 || ctx.config.dllOrder[loaderLibraryNameLowercase] > maxLoadOrder)
    ctx.config.dllOrder[loaderLibraryNameLowercase] = maxLoadOrder;

  // Resolve import symbols that we might need from the large loader
  loaderInitializeExportsImportFile = createLoaderImport(ctx, saver().save("__large_loader_register"));
  loaderTerminateExportsImportFile = createLoaderImport(ctx, saver().save("__large_loader_unregister"));
  loaderLinkImportsImportFile = createLoaderImport(ctx, saver().save("__large_loader_link"));
}

ImportFile* LargeIdataContents::createLoaderImport(COFFLinkerContext &ctx, StringRef symbolName) {
  StringRef loaderLibraryName = saver().save("LargeLoader.dll");

  size_t sizeOfData = (symbolName.size() + 1) + (loaderLibraryName.size() + 1);
  size_t totalImportSize = sizeof(coff_import_header) + sizeOfData;
  auto importBuffer = WritableMemoryBuffer::getNewMemBuffer(totalImportSize);

  // Populate the short import header with valid data for a function import by
  // name and the machine from the config file
  auto *hdr = reinterpret_cast<coff_import_header *>(importBuffer->getBufferStart());
  hdr->Sig1 = IMAGE_FILE_MACHINE_UNKNOWN;
  hdr->Sig2 = 0xFFFF;
  hdr->Version = 1;
  hdr->Machine = ctx.config.machine;
  hdr->SizeOfData = sizeOfData;
  hdr->TypeInfo = IMPORT_CODE | (IMPORT_NAME << 2);

  // Copy symbol name and DLL name into the import
  memcpy(importBuffer->getBufferStart() + sizeof(coff_import_header), symbolName.data(), symbolName.size() + 1);
  memcpy(importBuffer->getBufferStart() + sizeof(coff_import_header) + (symbolName.size() + 1), loaderLibraryName.data(), loaderLibraryName.size() + 1);

  // Create the file and populate it with the data
  MemoryBuffer &importBufferRef = *importBuffer;
  loaderImportData.push_back(std::move(importBuffer));
  ImportFile *loaderImportFile = make<ImportFile>(ctx, importBufferRef);
  ctx.symtab.addFile(loaderImportFile);

  // At this point, we have already performed the mark live analysis, so just
  // mark the import as live We do not need the thunk though, so mark it as dead
  // right away
  loaderImportFile->live = true;
  cast<ImportThunkChunk>(loaderImportFile->thunkSym->getChunk())->live = false;
  return loaderImportFile;
}

void LargeIdataContents::createRegisterInitializerChunk(COFFLinkerContext &ctx) {
  // Create callback chunk based on the machine architecture
  Chunk *callbackCodeChunk = nullptr;
  if (ctx.config.machine == IMAGE_FILE_MACHINE_AMD64) {
    callbackCodeChunk = make<LargeImportLoaderCallbackChunkX64>(loaderInitializeExportsImportFile->impSym, exportsSectionHeaderChunk);
  } else {
    fatal("Large Loader does not support architectures besides AMD64");
  }

  StringRef symbolName = ctx.saver.save("__large_loader_exports_initializer");
  Symbol* callbackSymbol = ctx.symtab.addSynthetic(symbolName, callbackCodeChunk);

  // Make sure the loader callback symbol has not been overwritten
  if (!isa<DefinedSynthetic>(callbackSymbol))
    fatal("Large Import Loader Exports Initializer symbol " + callbackSymbol->getName() + " has been replaced");

  // Create the chunk for the address of the initializer
  textChunks.push_back(callbackCodeChunk);
  initializerChunks.push_back(make<AbsoluteDefinedSymbolAddressChunk>(ctx, cast<Defined>(callbackSymbol)));
}

void LargeIdataContents::createUnregisterTerminatorChunk(COFFLinkerContext &ctx) {
  // Create callback chunk based on the machine architecture
  Chunk *callbackCodeChunk = nullptr;
  if (ctx.config.machine == IMAGE_FILE_MACHINE_AMD64) {
    callbackCodeChunk = make<LargeImportLoaderCallbackChunkX64>(loaderTerminateExportsImportFile->impSym, exportsSectionHeaderChunk);
  } else {
    fatal("Large Loader does not support architectures besides AMD64");
  }

  StringRef symbolName = ctx.saver.save("__large_loader_exports_terminator");
  Symbol* callbackSymbol = ctx.symtab.addSynthetic(symbolName, callbackCodeChunk);

  // Make sure the loader callback symbol has not been overwritten
  if (!isa<DefinedSynthetic>(callbackSymbol))
    fatal("Large Import Loader Exports Terminator symbol " + callbackSymbol->getName() + " has been replaced");

  // Create the chunk for the address of the initializer
  textChunks.push_back(callbackCodeChunk);
  terminatorChunks.push_back(make<AbsoluteDefinedSymbolAddressChunk>(ctx, cast<Defined>(callbackSymbol)));
}

void LargeIdataContents::createLinkInitializerChunk(COFFLinkerContext &ctx) {
  // Create callback chunk based on the machine architecture
  Chunk *callbackCodeChunk = nullptr;
  if (ctx.config.machine == IMAGE_FILE_MACHINE_AMD64) {
    callbackCodeChunk = make<LargeImportLoaderCallbackChunkX64>(loaderLinkImportsImportFile->impSym, sectionHeaderChunk);
  } else {
    fatal("Large Loader does not support architectures besides AMD64");
  }

  StringRef symbolName = ctx.saver.save("__large_loader_link_initializer");
  Symbol* callbackSymbol = ctx.symtab.addSynthetic(symbolName, callbackCodeChunk);

  // Make sure the loader callback symbol has not been overwritten
  if (!isa<DefinedSynthetic>(callbackSymbol))
    fatal("Large Import Loader Link Initializer symbol " + callbackSymbol->getName() + " has been replaced");

  // Create the chunk for the address of the initializer
  textChunks.push_back(callbackCodeChunk);
  initializerChunks.push_back(make<AbsoluteDefinedSymbolAddressChunk>(ctx, cast<Defined>(callbackSymbol)));
}

void LargeIdataContents::createLargeLoaderDllImport(COFFLinkerContext &ctx, StringRef dllName) {
  StringRef externalSymbolName = saver().save("__large_loader_exports_base");

  // Create local symbol name prefixed with the name of the DLL without the
  // extension, to avoid conflicts between different DLLs
  SmallString<64> dllNameWithoutExtension = dllName;
  sys::path::replace_extension(dllNameWithoutExtension, "");
  StringRef localSymbolName =
      saver().save(externalSymbolName + "_" + Twine(dllNameWithoutExtension));

  size_t sizeOfData = (localSymbolName.size() + 1) + (dllName.size() + 1) + (externalSymbolName.size() + 1);
  size_t totalImportSize = sizeof(coff_import_header) + sizeOfData;
  auto importBuffer = WritableMemoryBuffer::getNewMemBuffer(totalImportSize);

  // Populate the short import header with valid data for a function import by
  // name and the machine from the config file
  auto *hdr = reinterpret_cast<coff_import_header *>(importBuffer->getBufferStart());
  hdr->Sig1 = IMAGE_FILE_MACHINE_UNKNOWN;
  hdr->Sig2 = 0xFFFF;
  hdr->Version = 1;
  hdr->Machine = ctx.config.machine;
  hdr->SizeOfData = sizeOfData;
  // This is large exports section start being imported, so it is data
  // We use NAME_EXPORTAS because symbol being imported is always called
  // __large_loader_exports_base, but we cannot export it as such into
  // this file because the name would conflict between different DLLs So we
  // append the name of the DLL to the local name of the export, but use the
  // original name as external name that linker will look up
  hdr->TypeInfo = IMPORT_DATA | (IMPORT_NAME_EXPORTAS << 2);

  // Copy local symbol name, DLL name, and external symbol name into the import
  memcpy(importBuffer->getBufferStart() + sizeof(coff_import_header), localSymbolName.data(), localSymbolName.size() + 1);
  memcpy(importBuffer->getBufferStart() + sizeof(coff_import_header) + (localSymbolName.size() + 1), dllName.data(), dllName.size() + 1);
  memcpy(importBuffer->getBufferStart() + sizeof(coff_import_header) + (localSymbolName.size() + 1) + (dllName.size() + 1), externalSymbolName.data(), externalSymbolName.size() + 1);

  // Create the file and populate it with the data
  ImportFile *dllImportFile = make<ImportFile>(ctx, *importBuffer);
  dllImportData.push_back(std::move(importBuffer));
  dllImportFiles[dllName] = dllImportFile;
  importedDllNames.push_back(dllName);

  ctx.symtab.addFile(dllImportFile);
  // At this point, we have already performed the mark live analysis, so just mark the import as live
  dllImportFile->live = true;

  // Make sure the import symbol has actually been added
  if (dllImportFile->impSym == nullptr)
    fatal("Large Import Dll symbol has been replaced for DLL " + dllName);
}

void LargeIdataContents::buildSectionContents(COFFLinkerContext &ctx) {

  // Create chunks for imported export sections
  for (const StringRef &importedDllName : importedDllNames) {
    Symbol* dllImportExportSectionStartSymbol = dllImportFiles[importedDllName]->impSym;

    // Make sure DLL import symbol has not been replaced by user symbol
    if (!isa<DefinedImportData>(dllImportExportSectionStartSymbol))
      fatal("Large Import Dll Symbol has been replaced for DLL " + importedDllName);

    // Create the address chunk, and map the dll name to the index of the chunk in the list
    Chunk* exportSectionStartAddressChunk = make<AbsoluteDefinedSymbolAddressChunk>(ctx, cast<Defined>(dllImportExportSectionStartSymbol));
    importedDllNameToExportSectionIndex[importedDllName] = importedExportSectionChunks.size();
    importedExportSectionChunks.push_back(exportSectionStartAddressChunk);
  }

  // Create address table chunk for each import
  for (DefinedLargeImport* largeImport : imports) {
    Chunk *addressTableEntryChunk = make<NullChunk>(ctx.config.wordsize);

    largeImport->setLocation(addressTableEntryChunk);
    addressTableChunks.push_back(addressTableEntryChunk);
  }

  // Create import chunk for each import
  for (const DefinedLargeImport *largeImport : imports) {

    // Create chunk with the external name of the import
    Chunk *importNameChunk = make<StringChunk>(largeImport->getExternalName());
    nameChunks.push_back(importNameChunk);

    // Create import map entry chunk
    COFFLargeLoaderImport import{};
    // If dll name is empty, set export section index to 0xFFFF to indicate a wildcard import
    import.ExportSectionIndex = largeImport->getDLLName().empty() ? 0xFFFF : static_cast<uint16_t>(importedDllNameToExportSectionIndex.find(largeImport->getDLLName())->second);
    import.ImportKind = largeImport->getImportType();
    import.ImportFlags = largeImport->getImportFlags();
    import.NameLen = importNameChunk->getSize() - 1; // do not count null terminator as a part of name length

    Chunk* importChunk = make<LargeLoaderImportChunk>(import, importNameChunk);
    importChunks.push_back(importChunk);
  }

  // Create image name chunk
  Chunk *imageNameChunk = make<StringChunk>(sys::path::filename(ctx.config.outputFile));
  nameChunks.push_back(imageNameChunk);

  // Create import section header chunk
  COFFLargeLoaderImportSectionHeader sectionHeader{};
  sectionHeader.Version = 1;
  sectionHeader.NumExportSections = static_cast<uint16_t>(importedExportSectionChunks.size());
  sectionHeader.NumImports = static_cast<uint32_t>(importChunks.size());
  sectionHeader.SingleImportSize = static_cast<uint32_t>(importChunks[0]->getSize());
  sectionHeader.ImageFilenameLength = static_cast<uint32_t>(imageNameChunk->getSize() - 1);

  // Imported export section chunks are optional, if all imports are wildcard we will not have any
  Chunk *firstImportedSectionsChunk = importedExportSectionChunks.empty() ? nullptr : importedExportSectionChunks[0];
  sectionHeaderChunk = make<LargeLoaderImportSectionHeaderChunk>(sectionHeader, addressTableChunks[0], firstImportedSectionsChunk, importChunks[0], imageNameChunk);
}

struct LargeExportData {
  Defined* exportSymbol{};
  StringRef exportName;
  uint16_t exportKind{};
  uint64_t exportHash{};
};

LargeEdataContents::LargeEdataContents(COFFLinkerContext &ctx) {

  // Determine a number of hash buckets. We want 2 to 3 elements per hash bucket, at least 1 bucket, and only 1 bucket if there is less than 4 imports
  size_t numberOfExports = static_cast<uint32_t>(ctx.config.exports.size());
  size_t numberOfHashBuckets = numberOfExports >= 4 ? std::max<size_t>(numberOfExports / 3, 1) : 1;
  uint16_t hashingAlgo = LARGE_LOADER_HASH_ALGO_CityHash64;

  std::vector<SmallVector<size_t, 4>> exportHashBuckets;
  exportHashBuckets.insert(exportHashBuckets.end(), numberOfHashBuckets, SmallVector<size_t, 4>());
  std::vector<LargeExportData*> allExportData;

  // Assign exports into their relevant buckets
  for (Export &exp : ctx.config.exports) {
    // Make sure the symbol this export represents is actually defined
    if (!isa<Defined>(exp.sym))
      fatal("Symbol is not defined for export " + exp.sym->getName());

    // Create export data object for this export
    LargeExportData* exportData = make<LargeExportData>();
    exportData->exportSymbol = cast<Defined>(exp.sym);
    exportData->exportName = exp.exportName;
    exportData->exportKind = exp.data ? LARGE_LOADER_IMPORT_TYPE_DATA : LARGE_LOADER_IMPORT_TYPE_CODE;

    // Determine the hash of the export name. Note that export hash does not include the null terminator
    if (hashingAlgo == LARGE_LOADER_HASH_ALGO_CityHash64)
      exportData->exportHash = CityHash64(exportData->exportName.data(), exportData->exportName.size());
    else
      fatal("Unknown export hashing algorithm provided");

    // Add the export to the relevant export bucket and to the global list
    size_t exportIndex = allExportData.size();
    size_t exportBucketIndex = exportData->exportHash % numberOfHashBuckets;

    exportHashBuckets[exportBucketIndex].push_back(exportIndex);
    allExportData.push_back(exportData);
  }

  // Arrange exports in the order of the hash buckets, and then in their order inside the bucket
  for (const SmallVector<size_t, 4>& hashBucketContents : exportHashBuckets) {

    // Build a large loader export bucket from the data
    COFFLargeLoaderExportHashBucket hashBucket{};
    hashBucket.FirstExportIndex = static_cast<uint32_t>(exportTableChunks.size());
    hashBucket.NumExports = static_cast<uint32_t>(hashBucketContents.size());

    exportHashBucketTableChunks.push_back(make<LargeLoaderExportHashBucketChunk>(hashBucket));

    // Add export entries from the bucket into the sorted exports list
    for (size_t exportIndex : hashBucketContents) {
      LargeExportData* exportData = allExportData[exportIndex];

      // Add export RVA table entry for this export
      exportRVATableChunks.push_back(make<SymbolRVAChunk>(ctx, exportData->exportSymbol));

      // Add name chunk for this export name
      Chunk *exportNameChunk = make<StringChunk>(exportData->exportName);
      nameChunks.push_back(exportNameChunk);

      // Build large export for this export data and add it to the list
      COFFLargeLoaderExport largeExport{};
      largeExport.ExportHash = exportData->exportHash;
      largeExport.ImportKind = exportData->exportKind;
      largeExport.NameLen = exportData->exportName.size();

      exportTableChunks.push_back(make<LargeLoaderExportChunk>(largeExport, exportNameChunk));
    }
  }

  // Create image name chunk
  Chunk *imageNameChunk = make<StringChunk>(sys::path::filename(ctx.config.outputFile));
  nameChunks.push_back(imageNameChunk);

  // Create export section header now
  COFFLargeLoaderExportSectionHeader sectionHeader{};
  sectionHeader.Version = 1;
  sectionHeader.HashingAlgorithm = hashingAlgo;
  sectionHeader.NumExportBuckets = static_cast<uint32_t>(exportHashBucketTableChunks.size());
  sectionHeader.NumExports = static_cast<uint32_t>(exportTableChunks.size());
  sectionHeader.SingleExportSize = static_cast<uint32_t>(exportTableChunks[0]->getSize());
  sectionHeader.ImageFilenameLength = static_cast<uint32_t>(imageNameChunk->getSize() - 1);

  sectionHeaderChunk = make<LargeLoaderExportSectionHeaderChunk>(sectionHeader, exportRVATableChunks[0], exportHashBucketTableChunks[0], exportTableChunks[0], imageNameChunk);

  // Replace the large loader exports base symbol created by the Driver on startup with a defined synthetic symbol pointing at the start of the section
  Symbol *exportsBaseSymbol = ctx.symtab.addSynthetic("__large_loader_exports_base", sectionHeaderChunk);
  if (!isa<DefinedSynthetic>(exportsBaseSymbol))
    fatal("Large loaders exports base symbol has been replaced");
}
// </COFF_LARGE_EXPORTS>

std::vector<Chunk *> DelayLoadContents::getChunks() {
  std::vector<Chunk *> v;
  v.insert(v.end(), dirs.begin(), dirs.end());
  v.insert(v.end(), names.begin(), names.end());
  v.insert(v.end(), hintNames.begin(), hintNames.end());
  v.insert(v.end(), dllNames.begin(), dllNames.end());
  return v;
}

std::vector<Chunk *> DelayLoadContents::getDataChunks() {
  std::vector<Chunk *> v;
  v.insert(v.end(), moduleHandles.begin(), moduleHandles.end());
  v.insert(v.end(), addresses.begin(), addresses.end());
  return v;
}

uint64_t DelayLoadContents::getDirSize() {
  return dirs.size() * sizeof(delay_import_directory_table_entry);
}

void DelayLoadContents::create(Defined *h) {
  helper = h;
  std::vector<std::vector<DefinedImportData *>> v = binImports(ctx, imports);

  Chunk *unwind = newTailMergeUnwindInfoChunk();

  // Create .didat contents for each DLL.
  for (std::vector<DefinedImportData *> &syms : v) {
    // Create the delay import table header.
    dllNames.push_back(make<StringChunk>(syms[0]->getDLLName()));
    auto *dir = make<DelayDirectoryChunk>(dllNames.back());

    size_t base = addresses.size();
    Chunk *tm = newTailMergeChunk(dir);
    Chunk *pdataChunk = unwind ? newTailMergePDataChunk(tm, unwind) : nullptr;
    for (DefinedImportData *s : syms) {
      Chunk *t = newThunkChunk(s, tm);
      auto *a = make<DelayAddressChunk>(ctx, t);
      addresses.push_back(a);
      thunks.push_back(t);
      StringRef extName = s->getExternalName();
      if (extName.empty()) {
        names.push_back(make<OrdinalOnlyChunk>(ctx, s->getOrdinal()));
      } else {
        auto *c = make<HintNameChunk>(extName, 0);
        names.push_back(make<LookupChunk>(ctx, c));
        hintNames.push_back(c);
        // Add a synthetic symbol for this load thunk, using the "__imp___load"
        // prefix, in case this thunk needs to be added to the list of valid
        // call targets for Control Flow Guard.
        StringRef symName = saver().save("__imp___load_" + extName);
        s->loadThunkSym =
            cast<DefinedSynthetic>(ctx.symtab.addSynthetic(symName, t));
      }

      if (s->file->impECSym) {
        auto chunk = make<AuxImportChunk>(s->file);
        auxIat.push_back(chunk);
        s->file->impECSym->setLocation(chunk);

        chunk = make<AuxImportChunk>(s->file);
        auxIatCopy.push_back(chunk);
        s->file->auxImpCopySym->setLocation(chunk);
      }
    }
    thunks.push_back(tm);
    if (pdataChunk)
      pdata.push_back(pdataChunk);
    StringRef tmName =
        saver().save("__tailMerge_" + syms[0]->getDLLName().lower());
    ctx.symtab.addSynthetic(tmName, tm);
    // Terminate with null values.
    addresses.push_back(make<NullChunk>(8));
    names.push_back(make<NullChunk>(8));
    if (ctx.config.machine == ARM64EC) {
      auxIat.push_back(make<NullChunk>(8));
      auxIatCopy.push_back(make<NullChunk>(8));
    }

    for (int i = 0, e = syms.size(); i < e; ++i)
      syms[i]->setLocation(addresses[base + i]);
    auto *mh = make<NullChunk>(8);
    mh->setAlignment(8);
    moduleHandles.push_back(mh);

    // Fill the delay import table header fields.
    dir->moduleHandle = mh;
    dir->addressTab = addresses[base];
    dir->nameTab = names[base];
    dirs.push_back(dir);
  }

  if (unwind)
    unwindinfo.push_back(unwind);
  // Add null terminator.
  dirs.push_back(make<NullChunk>(sizeof(delay_import_directory_table_entry)));
}

Chunk *DelayLoadContents::newTailMergeChunk(Chunk *dir) {
  switch (ctx.config.machine) {
  case AMD64:
  case ARM64EC:
    return make<TailMergeChunkX64>(dir, helper);
  case I386:
    return make<TailMergeChunkX86>(ctx, dir, helper);
  case ARMNT:
    return make<TailMergeChunkARM>(ctx, dir, helper);
  case ARM64:
    return make<TailMergeChunkARM64>(dir, helper);
  default:
    llvm_unreachable("unsupported machine type");
  }
}

Chunk *DelayLoadContents::newTailMergeUnwindInfoChunk() {
  switch (ctx.config.machine) {
  case AMD64:
    return make<TailMergeUnwindInfoX64>();
    // FIXME: Add support for other architectures.
  default:
    return nullptr; // Just don't generate unwind info.
  }
}
Chunk *DelayLoadContents::newTailMergePDataChunk(Chunk *tm, Chunk *unwind) {
  switch (ctx.config.machine) {
  case AMD64:
    return make<TailMergePDataChunkX64>(tm, unwind);
    // FIXME: Add support for other architectures.
  default:
    return nullptr; // Just don't generate unwind info.
  }
}

Chunk *DelayLoadContents::newThunkChunk(DefinedImportData *s,
                                        Chunk *tailMerge) {
  switch (ctx.config.machine) {
  case AMD64:
  case ARM64EC:
    return make<ThunkChunkX64>(s, tailMerge);
  case I386:
    return make<ThunkChunkX86>(ctx, s, tailMerge);
  case ARMNT:
    return make<ThunkChunkARM>(ctx, s, tailMerge);
  case ARM64:
    return make<ThunkChunkARM64>(s, tailMerge);
  default:
    llvm_unreachable("unsupported machine type");
  }
}

EdataContents::EdataContents(COFFLinkerContext &ctx) : ctx(ctx) {
  // <COFF_LARGE_EXPORTS> When building large exports, we only want to emit a single normal export, which points to the start of the large loader exports section
  if (ctx.config.largeExports && !ctx.config.exports.empty()) {

    Chunk *dllNameChunk = make<StringChunk>(sys::path::filename(ctx.config.outputFile));
    Chunk *exportedSymbolNameChunk = make<StringChunk>("__large_loader_exports_base");
    Symbol *exportSectionBaseSymbol = ctx.symtab.find("__large_loader_exports_base"); // this will be created as undefined on the start by the Driver, and then later replaced
    if (exportSectionBaseSymbol == nullptr)
      fatal("Failed to find large loader exports base symbol. It should have been added by the Driver");

    Chunk *addressTab = make<SymbolRVAChunk>(ctx, exportSectionBaseSymbol); // symbol will be replaced with DefinedSynthetic when large export tables are created
    Chunk *ordinalTab = make<NullChunk>(sizeof(uint16_t)); // since we only have a single export, it's unbiased ordinal is always 0, written as uint16_t
    std::vector<Chunk *> exportNames = {exportedSymbolNameChunk};
    Chunk *nameTab = make<NamePointersChunk>(exportNames); // only have a single name for a single export
    Chunk *dir = make<ExportDirectoryChunk>(1, 1, 1, dllNameChunk, addressTab, nameTab, ordinalTab); // base ordinal is 1, max ordinal is 1, name count is 1

    chunks.push_back(dir);
    chunks.push_back(dllNameChunk);
    chunks.push_back(addressTab);
    chunks.push_back(nameTab);
    chunks.push_back(ordinalTab);
    chunks.push_back(exportedSymbolNameChunk);
    return;
  }
  // </COFF_LARGE_EXPORTS>
  unsigned baseOrdinal = 1 << 16, maxOrdinal = 0;
  for (Export &e : ctx.config.exports) {
    baseOrdinal = std::min(baseOrdinal, (unsigned)e.ordinal);
    maxOrdinal = std::max(maxOrdinal, (unsigned)e.ordinal);
  }
  // Ordinals must start at 1 as suggested in:
  // https://learn.microsoft.com/en-us/cpp/build/reference/export-exports-a-function?view=msvc-170
  assert(baseOrdinal >= 1);

  auto *dllName = make<StringChunk>(sys::path::filename(ctx.config.outputFile));
  auto *addressTab = make<AddressTableChunk>(ctx, baseOrdinal, maxOrdinal);
  std::vector<Chunk *> names;
  for (Export &e : ctx.config.exports)
    if (!e.noname)
      names.push_back(make<StringChunk>(e.exportName));

  std::vector<Chunk *> forwards;
  for (Export &e : ctx.config.exports) {
    if (e.forwardTo.empty())
      continue;
    e.forwardChunk = make<StringChunk>(e.forwardTo);
    forwards.push_back(e.forwardChunk);
  }

  auto *nameTab = make<NamePointersChunk>(names);
  auto *ordinalTab = make<ExportOrdinalChunk>(ctx, baseOrdinal, names.size());
  auto *dir =
      make<ExportDirectoryChunk>(baseOrdinal, maxOrdinal, names.size(), dllName,
                                 addressTab, nameTab, ordinalTab);
  chunks.push_back(dir);
  chunks.push_back(dllName);
  chunks.push_back(addressTab);
  chunks.push_back(nameTab);
  chunks.push_back(ordinalTab);
  chunks.insert(chunks.end(), names.begin(), names.end());
  chunks.insert(chunks.end(), forwards.begin(), forwards.end());
}

} // namespace lld::coff
