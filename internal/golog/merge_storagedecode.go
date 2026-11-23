// ELOG rewritten in Go - this file is deliberately empty.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

// ---------------------------------------------------------------------------
// Where the read path actually lives
// ---------------------------------------------------------------------------
//
// This file used to hold a second, parallel draft of the encoding-aware readers,
// which declared the same names as encoding_config.go and storage.go
// (FileDecoder, decoderForFile, newFileDecoderOf, parseFileDecoded,
// ReadLogFileEntries, ReadLogFileEntry, parseBlock, trimBlockTail,
// markerIndexes, nextMarker). Two owners of one name do not compile, and the two
// drafts disagreed about signatures, so the duplicate is gone and the decision is
// recorded here for whoever reads this next:
//
//   - storage.go owns the format: parseBlock, parseFile, the marker walking
//     (markerIndexes, nextMarker), the record tail (trimBlockTail), the banner
//     (splitBanner) and the byte helpers (indexByte, hasPrefixAt,
//     indexSeparator). Entry.Offset is produced there, from the RAW bytes.
//
//   - encoding_config.go owns the read decision of a whole file: which code page
//     a configuration scope, a logbook or one file is read with
//     (ConfigCodepage, LegacyCodepageForLogbook, GlobalLegacyCodepage,
//     codepageForFile), the per file decoder (FileDecoder, NewFileDecoder,
//     decoderForFile, lbDecoder) and the plain readers that need no logbook
//     (parseFileDecoded, ReadLogFileEntries, ReadLogFileEntry, DecodeEntryBlock).
//
//   - legacy.go owns the policy that decides, for a block of bytes, whether it is
//     UTF-8, legacy, or neither (decideFile, fileDecision.decodeBlock,
//     blockIsUTF8, the "Legacy codepage" option and its deprecated aliases), and
//     the conversion data types. legacy_write.go and legacy_convert.go own the
//     only code in the package that rewrites a log file, reachable only from
//     "gologd convert".
//
//   - encoding_read.go owns the readers that hold an offset or a block and have
//     neither a logbook nor a file decoder: DecodeBlockUTF8, RawBlocks,
//     ReadEntryAtOffset, DecodeTextForFile, DecodeSummaryForFile. They call
//     through to the two files above rather than deciding anything again, so a
//     legacy entry cannot read one way on a web page and another way in a search
//     result, a CSV export or the conversion report.
//
//   - encoding_util.go owns what a page, a feed, a mail or an attachment response
//     calls (DisplayText and friends, the form and meta charset constants,
//     TextualContentType, FilenameDisposition).
//
// The invariants that make those five files one design, restated because they are
// the reason the split is drawn where it is:
//
//   1. a Go string in memory is UTF-8, always;
//   2. every byte golog writes is UTF-8;
//   3. a legacy logbook is decoded at read time and never rewritten by a read;
//   4. an offset is a byte position in the RAW file and is never recomputed after
//      a decode;
//   5. converting a store to UTF-8 is the explicit "gologd convert" command, which
//      no request handler can reach.
//
// DELETE THIS FILE when the batch is merged; it declares nothing on purpose so
// that it cannot collide while the human sorts out which draft to keep.
