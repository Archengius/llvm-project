//===- MarkLive.cpp -------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "COFFLinkerContext.h"
#include "Chunks.h"
#include "Symbols.h"
#include "lld/Common/Timer.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/TimeProfiler.h"
#include <vector>

namespace lld::coff {

// Set live bit on for each reachable chunk. Unmarked (unreachable)
// COMDAT chunks will be ignored by Writer, so they will be excluded
// from the final output.
void markLive(COFFLinkerContext &ctx) {
  llvm::TimeTraceScope timeScope("Mark live");
  ScopedTimer t(ctx.gcTimer);

  // We build up a worklist of sections which have been marked as live. We only
  // push into the worklist when we discover an unmarked section, and we mark
  // as we push, so sections never appear twice in the list.
  SmallVector<SectionChunk *, 256> worklist;

  // COMDAT section chunks are dead by default. Add non-COMDAT chunks. Do not
  // traverse DWARF sections. They are live, but they should not keep other
  // sections alive.
  for (Chunk *c : ctx.driver.getChunks())
    if (auto *sc = dyn_cast<SectionChunk>(c))
      if (sc->live && !sc->isDWARF())
        worklist.push_back(sc);

  auto enqueue = [&](SectionChunk *c) {
    if (c->live)
      return;
    c->live = true;
    worklist.push_back(c);
  };

  std::function<void(Symbol *)> addSym;

  auto addImportFile = [&](ImportFile *file) {
    file->live = true;
    if (file->impchkThunk && file->impchkThunk->exitThunk)
      addSym(file->impchkThunk->exitThunk);
  };

  addSym = [&](Symbol *b) {
    if (auto *sym = dyn_cast<DefinedRegular>(b)) {
      enqueue(sym->getChunk());
    } else if (auto *sym = dyn_cast<DefinedImportData>(b)) {
      addImportFile(sym->file);
    } else if (auto *sym = dyn_cast<DefinedImportThunk>(b)) {
      addImportFile(sym->wrappedSym->file);
      sym->getChunk()->live = true;
    }
    // <COFF_LARGE_EXPORTS>
    else if (auto *sym = dyn_cast<DefinedLargeImport>(b)) {
      sym->file->markLive();
      // Make sure to mark both the import check thunk, and it's exit thunk as referenced
      if (sym->file->impchkThunk)
        sym->file->impchkThunk->live = true;
      if (sym->file->impchkThunk && sym->file->impchkThunk->exitThunk)
        addSym(sym->file->impchkThunk->exitThunk);
    }
    else if (auto *sym = dyn_cast<DefinedLargeImportThunk>(b)) {
      auto wrappedFile = sym->wrappedSym->file;
      wrappedFile->markLive();
      sym->getChunk()->live = true;
      // Make sure to mark both the import check thunk, and it's exit thunk as referenced
      if (wrappedFile->impchkThunk)
        wrappedFile->impchkThunk->live = true;
      if (wrappedFile->impchkThunk && wrappedFile->impchkThunk->exitThunk)
        addSym(wrappedFile->impchkThunk->exitThunk);
    }
    // </COFF_LARGE_EXPORTS>
  };

  // Add GC root chunks.
  for (Symbol *b : ctx.config.gcroot)
    addSym(b);

  while (!worklist.empty()) {
    SectionChunk *sc = worklist.pop_back_val();
    assert(sc->live && "We mark as live when pushing onto the worklist!");

    // Mark all symbols listed in the relocation table for this section.
    for (Symbol *b : sc->symbols())
      if (b)
        addSym(b);

    // Mark associative sections if any.
    for (SectionChunk &c : sc->children())
      enqueue(&c);

    // Mark EC entry thunks.
    if (Defined *entryThunk = sc->getEntryThunk())
      addSym(entryThunk);
  }
}
}
