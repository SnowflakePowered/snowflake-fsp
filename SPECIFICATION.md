# Snowflake Projected File System

The Snowflake Projected File System (`snowflake-projfs`) allows an emulator orchestrator to project a virtual directory
hierarchy from a backing file system while preserving most of the semantics of the underlying filesystem. With `projfs`,
orchestrator plugins can present to an emulator a directory hierarchy that assembles files and data from multiple
locations on the underlying filesystem. This allows ROMs, DLC, save games, and emulator files to be kept separate and isolated, as
well as ensuring the reliability and reproducibility of an emulating instance.

This document is not explicitly API documentation for `projfs`, but describes the semantics of `projfs`, particularly
on how they differ from the semantics of the underlying filesystem. Oftentimes, `projfs` *defers* semantics to the
underlying filesystem, and thus are OS-dependent, but this behaviour should match up with what is expected by the emulator
executable running on that OS.

## Concepts

* Projections and Projection Types
* Canonical Paths
* Projection Definition Language

### Projections and Projection Types

A _projection_ refers to either the directory hierarchy presented by the projected filesystem, or the individual entries
(files, directories) in such a hierarchy. For clarity, the latter can be referred as _projection entries_ as well.

A projection is always rooted at the mount point, either a folder or a drive letter on Windows. All entries are relative
to this mount point. There are three types of projection entries with differing semantics in their immutability. Note that
all projection types allow write-restrictions on top of the permissions model of the underlying target. In other words,
a projection can project a file or directory on the underlying filesystem as read-only, on top of the existing security
attributes of the file or directory on the underlying filesystem.

| PDL | Type      | Can Delete? | Can Add/Remove/Move Children? (with R/W access) | Can have Projections as Children? | Inherits Security from Target |
|-----|-----------|-------------|-------------------------------------------------|-----------------------------------|-------------------------------|
| `f` | File      | No          | N/A                                             | N/A                               | Yes                           |
| `d` | Directory | No          | No                                              | Yes                               | N/A                           |
| `p` | Portal    | No          | Yes                                             | No                                | Yes                           |

A **file** can be thought of like a symbolic link to another file on the underlying filesystem. Given read-write access, 
reads and writes to a file will affect the target it points to on the underlying filesystem. It inherits the security 
attributes (modes) from its target. 

A **directory** is an **immutable** virtual directory that only exists within the projection and is not backed by the 
underlying filesystem. **Only directories can have projections (directories, files, and portals) as children.**
The children of a directory can not be renamed, moved, or deleted, nor can additional files be created within a directory. In other
words, the contents of a directory are fixed at creation, and no new entries can be created or deleted without remounting
the projected filesystem with a new hierarchy. 

Because there is no backing target on the underlying filesystem, directories inherit their security attributes from the 
filesystem host executable. The mounted root is a directory of all the top-level entries in the Projection Definition 
Language that describes the hierarchy of the projection.

A **portal** can be thought of like a symbolic link to another directory on the underlying filesystem. Portals 'punch' through
the immutability of a mounted projected filesystem, and fully inherit the semantics of the target directory[^1]. Since portals
are backed by an actual directory on the underlying filesystem, files and folders can be created, moved, and deleted **within** 
the portal. However, they **can not be moved out of the portal**, even through to another portal. Portals are useful to 
specify a location to store mutable data such as savegames and writable NAND directories. Portals can not contain projection entries,
and are effectively a 'black hole' in the projection. 

Portals can also be set to read-only, which disallows creation, movement, and deletion of files as well as writes to any files
within the portal. Read-only restrictions can also be set at a path granularity, where only files and directories that match
names have read-only restrictions. This can be used to 'protect' accidental mutation of a folder by user error or a bug
in the emulator executable.

Because of their immutability, directories and files are ideal for specifying the file hierarchy of a complex ROM. For example,
an orchestrator can specify a hierarchy that combines the base game image, with some DLC in another folder, without needing to
copy any files on the underlying filesystem.

The projected filesystem does not support editing the security attributes of any entry, whether projected or through a portal.

[^1]: Except alternate streams, extended attributes, and symbolic links which are unsupported for the time being in `projfs`. Support may be added at a later time.

### Canonical Paths

Paths in `snowflake-projfs` are represented as _canonical paths_, which are somewhat Unix-like with a few differences.
A canonical path always represents the path separator as `/` (U+002F Solidus), and **never** has trailing path
separators.

However, the encoding of a canonical path is left OS and filesystem dependent. On Unix, canonical paths must be *convertable* to
any valid byte sequence that does not contain `0x0`. On Windows, canonical paths must be *convertable* to UTF-16 byte
sequences
allowing unpaired surrogates.

In effect, this means that canonical paths are, just like OS-dependent paths, treated as byte sequences with some
additional
restrictions and have no specified encoding. A byte sequence is transformed into a canonical path through
canonicalization,
where `..` and `.` are normalized away, and the path separator  `\` (U+005C Reverse Solidus) is replaced with `/` on
Windows.
Canonical paths are always rooted at `/` which represent the *root* of the projection, and are always absolute.

Note that this **only affects** the initial specification of a directory hierarchy in the Projection Definition
Language (PDL),
and the internal transformation of an OS-path to a canonical path when doing a path lookup in the Projection.

Canonical paths are never exposed as part of the projected filesystem, and applications running on top of `projfs` will
use the path scheme that is expected for the target operating system and underlying filesystem.

### Projection Definition Language
TODO: describe PDL