//===- COFFLargeImport.h - COFF large import implementation     -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// COFF Large Import file is a special file type containing the minimal information
// needed to represent a Large Export entry in another binary that can be linked against
// in runtime using the Large Export Linker
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBJECT_COFFLARGEIMPORT_H
#define LLVM_OBJECT_COFFLARGEIMPORT_H

#include "llvm/Support/Endian.h"
#include <cstddef>
#include <cstdint>

namespace llvm {
namespace object {

enum COFFLargeLoaderVersion : unsigned short int {
  LARGE_LOADER_VERSION_INITIAL = 1, /// Initial Large Loader implementation for AMD64 architecture
  LARGE_LOADER_VERSION_ARM64EC_EXPORTAS = 2, /// Large Loader compatibility with ARM64 and ARM64EC, EXPORTAS support in export definitions
};

enum COFFLargeLoaderImportType : unsigned char {
  LARGE_LOADER_IMPORT_TYPE_INVALID = 0,
  LARGE_LOADER_IMPORT_TYPE_CODE = 1,
  LARGE_LOADER_IMPORT_TYPE_DATA = 2,
  LARGE_LOADER_IMPORT_TYPE_WILDCARD = 0xFF,
};

enum COFFLargeLoaderHashAlgo : unsigned char {
  LARGE_LOADER_HASH_ALGO_CityHash64 = 0, /// CityHash64 over the name bytes, not including the null terminator
};

enum COFFLargeLoaderImportFlags : unsigned char {
  LARGE_LOADER_IMPORT_FLAGS_NONE = 0x0, /// No flags
  LARGE_LOADER_IMPORT_FLAGS_WILDCARD_LOOKUP_WIN32_EXPORT_DIRECTORY = 0x01, /// If this is a wildcard import that cannot be resolved in any Large Exports enabled DLL, look it up in loaded Modules Export Directories
  LARGE_LOADER_IMPORT_FLAGS_SYNTHETIC = 0x02, /// This import is synthetic, it was created by the linker on demand and does not come from a normal import library
};

struct COFFLargeImportHeader {
  char Signature[8]; /// !<limp>\n
  support::ulittle16_t Version; /// Version of the Large Loader specification. One of the values in COFFLargeLoaderVersion
  support::ulittle16_t Machine; /// COFF machine type for this import library
  char Type; /// Type of the import. One of values in COFFLargeLoaderImportType
  char Flags; /// Flags set on this import. A bitmask of values in COFFLargeLoaderImportFlags
  support::ulittle16_t SizeOfExternalSymbolName; /// Size of the external symbol name. Name is not null terminated.
  support::ulittle16_t SizeOfDllNameHint; /// Size of the dll name hint. If empty, this is a wildcard import that can be resolved from any loaded DLL. Name is not null terminated.
  support::ulittle16_t SizeOfInternalSymbolName; /// Size of the internal symbol name. Name is not null terminated. If this is zero, internal name is the same as external name. Only present if Version >= 2
};

struct COFFLargeLoaderImport {
  support::aligned_ulittle16_t ExportSectionIndex; /// Index of the export section to which this import maps. 0xFFFF means wildcard, e.g. lookup import in any presently loaded library
  char ImportKind; /// Kind of this import. One of values in COFFLargeLoaderImportType
  char ImportFlags; /// Flags set on this import. A bitmask of values in COFFLargeLoaderImportFlags
  support::aligned_ulittle32_t NameLen; /// Length of the import name. Does not include the null terminator
  support::aligned_ulittle32_t NameOffset; /// Offset to the start of the name data from the start of this import. Name is null terminated
  support::aligned_ulittle32_t Pad; /// Must always be 0
};

struct COFFLargeLoaderImportDirectory {
  support::aligned_ulittle16_t Version; /// Version of the Large Loader specification. One of the values in COFFLargeLoaderVersion
  support::aligned_ulittle16_t NumExportSections; /// Number of imported export sections, e.g. number of DLLs imported as large imports
  support::aligned_ulittle32_t NumImports; /// Total number of large imports
  support::aligned_ulittle32_t SingleImportSize; /// Size, in bytes, of a single import in the import table
  support::aligned_ulittle32_t AddressTableOffset; /// Offset to the address table from the start of the section. Element size is sizeof(uintptr_t) for the target platform
  support::aligned_ulittle32_t ImportedExportSectionsOffset; /// Offset to the export sections table from the start of the section. Element size is sizeof(uintptr_t) for the target platform
  support::aligned_ulittle32_t ImportTableOffset; /// Offset to the import table from the start of the section. Element size is SingleImportSize
  support::aligned_ulittle32_t ImageFilenameOffset; /// Offset to the name of this image from the start of the section. Used for debugging and error messages. Name is null terminated
  support::aligned_ulittle32_t ImageFilenameLength; /// Length of the name of the image. Does not include null terminator
  support::aligned_ulittle32_t AuxiliaryAddressTableOffset; /// Offset to the auxiliary address table from the start of the section. Only present on ARM64EC images with loader version >= 2. Value is 0 on non-ARM64EC images
};

struct COFFLargeLoaderExport {
  support::aligned_ulittle64_t ExportHash; /// Hash of this export. Algorithm used is a part of the section header
  support::aligned_ulittle16_t Pad[3]; /// Padding. Must always be 0
  support::aligned_ulittle16_t ImportKind; /// Kind of this export. One of values in COFFLargeImportType
  support::aligned_ulittle32_t NameLen; /// Length of the import name. Does not include null terminator
  support::aligned_ulittle32_t NameOffset; /// Offset to the start of the name data from the start of this export. Name is null terminated
};

struct COFFLargeLoaderExportHashBucket {
  support::aligned_ulittle32_t FirstExportIndex; /// Index of the first export in this bucket into export map
  support::aligned_ulittle32_t NumExports; /// Number of exports in this bucket, starting from FirstExportIndex
};

struct COFFLargeLoaderExportDirectory {
  support::aligned_ulittle16_t Version; /// Version of the Large Loader specification. One of the values in COFFLargeLoaderVersion
  support::aligned_ulittle16_t HashingAlgorithm; /// ID of the hashing algorithm used for hashing export names. One of values in COFFLargeLoaderHashAlgo
  support::aligned_ulittle32_t NumExportBuckets; /// Number of export hash buckets
  support::aligned_ulittle32_t NumExports; /// Total number of large exports
  support::aligned_ulittle32_t SingleExportSize; /// Size, in bytes, of a single export in the export table
  support::aligned_ulittle32_t ExportRVATableOffset; /// Offset to the Export RVA table from the start of the section. Element size is sizeof(uintptr_t) for the target platform. Values are offsets of each export address from the section start.
  support::aligned_ulittle32_t ExportHashBucketTableOffset; /// Offset to the export bucket table from the start of the section. Element size is sizeof(COFFLargeLoaderExportHashBucket)
  support::aligned_ulittle32_t ExportTableOffset; /// Offset to the export table from the start of the section. Element size is SingleExportSize
  support::aligned_ulittle32_t ExportDirectoryRVA; /// RVA of this export directory. This can be used to calculate the base address of the image
  support::aligned_ulittle32_t ImageFilenameOffset; /// Offset to the name of this image from the start of the section. Used for debugging and error messages. Name is null terminated
  support::aligned_ulittle32_t ImageFilenameLength; /// Length of the name of the image. Does not include null terminator
  support::aligned_ulittle32_t AuxExportRVATableOffset; /// Added in Version 2. Only present on ARM64EC, value is zero on other architectures. Offset to the Auxiliary RVA table containing RVAs of exported native ARM64EC code. Normal export table contains x64 code instead.
};

}
}

#endif // LLVM_OBJECT_COFFLARGEIMPORT_H