# Windows Compatibility Plan for Borg Backup

## Overview

This document outlines the plan to improve Windows compatibility in Borg Backup, focusing on path handling, pattern matching, and archive operations. The goal is to ensure that Borg works correctly on Windows while maintaining cross-platform archive compatibility.

---

## Core Strategy

### Forward Slash Standard
- **Internal representation**: All paths within Borg (in archives, pattern matching, path manipulation) use forward slashes (`/`) as the path separator.
- **Rationale**: Forward slashes work on all platforms (POSIX and Windows), simplifying internal logic and ensuring cross-platform archive compatibility.

### Boundary Normalization
- **Incoming normalization (Windows)**: Convert backslashes (`\`) to forward slashes (`/`) at entry points where paths enter Borg from the Windows filesystem or user input.
  - **Exception**: User-provided patterns (include/exclude patterns, regex patterns, etc.) must NOT be normalized. Normalization would break complex patterns. Windows users are expected to provide POSIX-style patterns using forward slashes (`/`), just like POSIX users. Normalization only applies to filesystem paths (e.g., during archive creation), not to patterns.
- **Outgoing normalization**: Minimal or no conversion when paths leave Borg to the filesystem, as Windows APIs accept forward slashes.
- **Literal backslashes from POSIX**: When extracting archives created on POSIX systems that contain literal backslashes in filenames, replace `\` with `%` on Windows to prevent misinterpretation as path separators.

### Security
- Prevent directory traversal attacks by rejecting paths containing `\..` or `..\` patterns, even on POSIX systems.
- This ensures that archives created on one platform cannot exploit path handling differences on another platform.

### Replacement Character Choice

**Why `%` as the replacement character:**
- It's a valid filename character on both POSIX and Windows
- It's relatively uncommon in typical filenames
- It's visually distinct from path separators

**Known limitation:**
- Collisions are possible if a POSIX file has `%` in its name and another file has `\` in its name. Both would map to the same name on Windows (e.g., `file%name.txt` and `file\name.txt` both become `file%name.txt`).
- This is an acceptable trade-off for simplicity.
- Users can avoid collisions by not using `%` in POSIX filenames when creating archives intended for Windows extraction.

### Windows Drive Letters
- Handling of Windows drive letters (e.g., `C:`) in archive paths is explicitly deferred and out of scope for this phase. The current behavior (if any) should remain unchanged.

### Keep it simple
- Avoid complex platform-specific logic where possible.
- Leverage the fact that Windows APIs accept forward slashes in most contexts.

### Critical: `os.path.normpath` vs `posixpath.normpath`

**The Problem:**
- `os.path.normpath` is platform-dependent:
  - On POSIX: Collapses `..` and `.`, removes redundant `/`, keeps `/` as separator
  - On Windows: Collapses `..` and `.`, removes redundant separators, **converts `/` to `\`**
- Using `os.path.normpath` on Windows **breaks the forward-slash standard** by converting all `/` to `\`

**The Solution:**
- **Always use `posixpath.normpath` instead of `os.path.normpath`** for internal path normalization
- `posixpath.normpath` always uses `/` as the separator, regardless of the platform
- This ensures consistent behavior across platforms and maintains the forward-slash standard

**Where this matters:**
- Pattern matching (`patterns.py`)
- Path manipulation in archive creation (`create_cmd.py`)
- Path specifications (`parseformat.py`)
- Helper functions (`fs.py`)
- Archive operations (`archive.py`)

### Critical: `os.path.join` vs `posixpath.join`

**The Problem:**
- `os.path.join()` uses `os.sep` (backslash on Windows) to join path components
- This breaks the forward-slash standard by introducing backslashes into internal paths

**The Solution:**
- **Use `posixpath.join()` instead of `os.path.join()`** for internal path operations
- `posixpath.join()` always uses `/` as the separator, regardless of platform

**Where this matters:**
- Archive creation (`create_cmd.py`)
- Path specifications (`parseformat.py`)
- Any internal path manipulation that should maintain the forward-slash standard

**Exception:**
- `os.path.join()` may be acceptable when joining filesystem paths for OS operations (e.g., extraction destination paths), but `posixpath.join()` works on Windows too since Windows APIs accept forward slashes

### Critical: Avoid `os.path.abspath()` and `os.path.realpath()`

**The Problem:**
- Both functions call `os.path.normpath()` internally
- On Windows, this converts all `/` to `\`

**The Solution:**
- For internal paths: Apply boundary normalization first, then use `posixpath.normpath()`
- Avoid `os.path.abspath()` and `os.path.realpath()` for internal path handling
- If absolute paths are needed, construct them using `posixpath.join()` with a normalized base path

**Where this matters:**
- Path specifications (`parseformat.py`)
- Any code that needs to resolve relative paths to absolute paths for archive storage
- **Implementation Note**: To get an absolute path on Windows to use with `posixpath`:
  1. Get CWD: `cwd = os.getcwd()`
  2. Normalize CWD (boundary normalization): `cwd = cwd.replace('\\', '/')`
  3. Use `posixpath.join(cwd, path)` (assuming `path` is already normalized)

---

## Section 1: Path Sanitization and Boundary Normalization

### Entry Points for Normalization

#### 1. `src/borg/helpers/parseformat.py` (PathSpec)

**Current behavior**: Handles path specifications from the command line.

**Changes needed**:
- Normalize backslashes to forward slashes on Windows **only for filesystem paths** (paths being archived).
- Patterns must NOT be normalized. Patterns can be complex (especially regex patterns) and normalization would break them.
- Windows users are expected to provide POSIX-style patterns with forward slashes.

#### 2. `src/borg/archiver/create_cmd.py` (do_create and _rec_walk)

**Current behavior**: Walks the filesystem to create archives.

**Changes needed**:
- In `_rec_walk`, normalize paths from the filesystem walker to use forward slashes on Windows.
- This ensures all paths entering the archive use the forward slash standard.

#### 3. Archive Reading (Item.path and Item.target)

**Current behavior**: Reads paths from archives.

**Changes needed**:

##### `Item.path`
- Already uses `decode=to_sanitized_path`.
- Ensure `to_sanitized_path` in `fs.py` calls `make_path_safe`, which handles the replacement of literal backslashes with `%` on Windows.

##### `Item.target`
- Used in Borg 2 for **symlink targets only**. Hardlinks are identified by `hlid`.

**Encoding (Archive Creation on Windows)**:
- Symlink targets from the Windows filesystem must be normalized to use forward slashes before storing in the archive.
- Example: `..\sibling` → `../sibling`, `C:\foo\bar` → `C:/foo/bar`
- This can be done in the `Item.target` encode method.
- Add an `encode` parameter to the `Item.target` property definition in `item.pyx` that calls a new helper function (e.g., `encode_link_target`) in `fs.py` to normalize `\` to `/` on Windows.

**Decoding (Archive Reading on Windows)**:
- Add `decode=to_safe_link_target` to handle literal backslashes from POSIX archives.
- When a POSIX archive contains a symlink target with a literal backslash in a filename (e.g., `foo\bar` as a single filename component), apply the replacement character (`%`) on Windows to prevent misinterpretation as a path separator.

**Extraction on Windows**:
- Symlink targets stored with `/` can be used as-is during extraction.
- The Windows API (including `os.symlink()`) accepts forward slashes in symlink targets.
- No conversion back to `\` is needed.

##### `Item.source`
- Legacy field from Borg 1.x, used for both symlink and hardlink targets in Borg 1.x.
- In Borg 2, `Item.source` is **ONLY** used during repository transfer from Borg 1.x to Borg 2.
- at transfer time, borg2 will upgrade the item:
  - for symlinks, `Item.source` is used as-is (no changes)
  - for hardlinks, `Item.source` will be transformed into `Item.hlid` by existing code. The upgraded item will not have a `Item.source` field nor a `Item.target` field.

---

### Helper Functions in `src/borg/helpers/fs.py`

#### `make_path_safe`
- Replace literal `\` with `%` on Windows for file paths.
- Add a security check to reject `\..` and `/..` equivalently, and also reject `..\` and `../` equivalently, even on POSIX to prevent cross-platform directory traversal.
- This security check applies only to file paths (`Item.path`) and NOT to link targets (`Item.target`).

#### `to_safe_link_target`
- New helper to replace literal `\` with `%` on Windows for link targets.
- This function should be called from the `Item.target` decode method.
- Unlike `make_path_safe`, this function should NOT apply the security check for `\..` patterns (as per the specification above, security checks apply only to `Item.path`).

#### `get_strip_prefix`
- Clarification: Boundary normalization (conversion of `\` to `/` on Windows) **must happen before** this function is called.
- The function only needs to detect the slashdot hack using `/./` and **does not need to care about backslashes**.
- **Critical fix**: In the return statement `return os.path.normpath(path[:pos]) + os.sep`, replace with `return posixpath.normpath(path[:pos]) + "/"` to maintain forward-slash standard.
- The current code uses `os.path.normpath` which would convert `/` to `\` on Windows.

#### `remove_dotdot_prefixes`
- Clarification: Boundary normalization (conversion of `\` to `/` on Windows) **must happen before** this function is called.
- The function **does not need to care about backslashes**.
- Remove the redundant backslash normalization (`replace("\\", "/")`) as this is now handled by boundary normalization.
- Drive letter handling should remain as is.

---

## Section 2: Pattern Matching

### Files to Update

#### `src/borg/patterns.py`

**Current behavior**: Implements pattern matching for include/exclude rules.

**Changes needed**:
- **Critical**: Replace all `os.path.normpath` with `posixpath.normpath` to prevent `/` → `\` conversion on Windows.
- Replace all `os.path.sep` with `/` in pattern matching logic.
- Ensure that patterns are matched against paths using forward slashes.
- The pattern matcher should only handle `/` as the separator.

**Specific changes by pattern class**:
- `PathFullPattern._prepare()`: Replace `os.path.normpath(pattern).lstrip(os.path.sep)` with `posixpath.normpath(pattern).lstrip("/")`
- `PathPrefixPattern._prepare()`: Replace `os.path.sep` with `"/"` and `os.path.normpath` with `posixpath.normpath`
- `FnmatchPattern._prepare()`: Replace `os.path.sep` with `"/"` and `os.path.normpath` with `posixpath.normpath`
- `ShellPattern._prepare()`: Replace `os.path.sep` with `"/"` and `os.path.normpath` with `posixpath.normpath`
- `RegexPattern._match()`: Already handles separator normalization correctly; no changes needed
- Pattern `_match()` methods in `PathPrefixPattern`, `FnmatchPattern`, and `ShellPattern`: Replace `os.path.sep` with `"/"`

### User Expectation

**Important**: Windows users are expected to provide the same patterns as POSIX (Unix) users.
- Patterns must use forward slashes (`/`) as path separators.
- Patterns can be rather complex (especially regex patterns).
- **We cannot and must not normalize these patterns.**
- Patterns must be used exactly as provided by the user.

**Rationale**: Normalizing patterns would break complex patterns, especially regex patterns. By requiring Windows users to use POSIX-style patterns, we maintain consistency and avoid breaking pattern logic.

---

## Section 3: Archive Creation

### Files to Update

#### `src/borg/archiver/create_cmd.py`

**Current behavior**: Implements the `borg create` command.

**Changes needed**:
- In `_rec_walk`, normalize the `path` variable to use forward slashes immediately after receiving it from the filesystem walker, before passing it to the matcher or any other processing.
- This ensures all downstream operations work with normalized paths.
- Convert `path` to use forward slashes at the start of the creation loop.
- **Critical**: Replace `os.path.normpath` with `posixpath.normpath` to prevent `/` → `\` conversion on Windows:
  - In `do_create()` method: when normalizing paths from command-line arguments
  - In `_rec_walk()` method: when joining path with directory entry name, use `posixpath.normpath(posixpath.join(path, dirent.name))`
- **Critical**: Replace `os.path.join` with `posixpath.join` to prevent backslash introduction on Windows:
  - When joining `path` with `dirent.name` in `_rec_walk()`
  - When joining `path` with `tag_name` for cache tag handling
  - Any other path joining operations for archive paths (not filesystem destination paths)

---

## Section 4: Archive Path Manipulation

### Files to Update

#### `src/borg/archiver/extract_cmd.py`

**Current behavior**: Implements the `borg extract` command with `--strip-components`.

**Changes needed**:
- In `extract_cmd.py`, replace `os.sep` with `/` when stripping path components.
- Ensure that `strip_components` logic works with forward slashes.

#### `src/borg/archive.py` (Archive.create_helper)

**Current behavior**: Helper method for archive creation.

**Changes needed**:
- Review `Archive.create_helper` for any uses of `os.sep` in path operations and replace with `/`.
- In `Archive.create_helper`, replace `os.sep` with `/` when checking for prefixes and stripping them.
- **Critical**: Replace `os.path.normpath` with `posixpath.normpath` in tar import functionality:
  - When normalizing `tarinfo.name` during tar import
  - When normalizing `tarinfo.linkname` during tar import
- These normalizations must preserve forward slashes to maintain the forward-slash standard.

#### `src/borg/helpers/parseformat.py` (PathSpec)

**Current behavior**: Handles path specifications from the command line.

**Changes needed**:
- **Critical**: Replace `os.path.normpath` with appropriate handling in `PathSpec` class:
  - For pattern paths: use `posixpath.normpath` directly (no boundary normalization needed)
  - For filesystem paths: apply boundary normalization first (convert `\` to `/` on Windows), then use `posixpath.normpath`
- **Critical**: Replace `os.path.abspath` with getcwd() + boundary normalization + `posixpath.normpath`:
  - When resolving filesystem paths to absolute paths, first apply boundary normalization (`\` → `/` on Windows)
  - Like `os.path.abspath`, but uses `os.getcwd()` (normalized to `/`) as base if needed.
  - Construct absolute paths using `posixpath.join()` with the normalized CWD.
- Ensure boundary normalization happens BEFORE `posixpath.normpath` for filesystem paths
- Patterns must NOT have their backslashes normalized (they should be treated as literal characters)

### Extraction on Windows

**Important clarification**:
- **No conversion back to native paths (backslashes) is needed** when extracting files on Windows.
- The Windows API accepts forward slashes as path separators for **file paths** (not just symlink targets).
- Archive paths with `/` can be used directly for filesystem operations.
- The replacement character (`%`) representing literal backslashes from POSIX filenames **must be extracted as-is**.
- **Rationale**: To avoid giving Windows a backslash that was not meant to be a path separator.

---

## Section 5: FUSE Operations (Deferred)

### Status
- FUSE support on Windows is limited and not a priority for this phase.
- Changes to FUSE code are deferred to a future phase.

### Future Considerations
- If FUSE is implemented on Windows, ensure that paths are normalized consistently.
- Consider whether FUSE should be disabled or skipped in tests until proper Windows support is added.

---

## Section 6: Test Suite Updates

### 1. Existing Test Updates

- **`rejected_dotdot_paths`**: Update to include `\..` and `..\` patterns for
  security validation.
- **`test_regex_pattern`**: Update to ensure regex patterns work with the
  forward-slash standard.
- **`test_archived_paths`**: Simplify after boundary normalization is
  implemented.
- **New test cases**: Add Windows-style path tests in `test_create.py`,
  `test_extract.py`, and `test_patterns.py`.

### 2. Symlink and Hardlink Handling

- **Test symlink target normalization on Windows**: Create a symlink with a
  backslash target (e.g., `..\sibling`) on Windows, create an archive, and
  verify the target is stored with forward slashes in the archive.
- **Test symlink extraction on Windows**: Extract an archive containing
  symlinks with forward-slash targets on Windows and verify the symlinks work
  correctly.
- **Test literal backslashes in symlink targets from POSIX archives**: Create
  an archive on POSIX with a symlink target containing a literal backslash
  (e.g., `foo\bar` as a single filename component), extract on Windows, and
  verify the backslash is replaced with `%`.
- **Test hardlink handling**: Verify that hardlinks are handled consistently
  across platforms with the forward-slash standard.

### 3. Extraction with Replacement Character

- **Test extraction of files with literal backslashes from POSIX archives**:
  Create an archive on POSIX with filenames containing literal backslashes,
  extract on Windows, and verify the backslashes are replaced with `%`.
- **Test replacement character preservation**: Verify that `%` is not
  converted back to `\` during extraction on Windows.
- **Test collision scenarios**: Test edge cases where a POSIX archive
  contains both a file with `%` in its name and a file with `\` in its name
  (both would map to the same name on Windows).

### 4. Security Checks

- **Test `\..` and `..\` rejection**: Verify that paths containing `\..` or
  `..\` are rejected on all platforms (POSIX and Windows).
- **Test security check in `make_path_safe`**: Verify that the security check
  correctly identifies and rejects malicious patterns in `Item.path` only
  (NOT in `Item.target`, as per the specification in Section 1).
- **Test cross-platform security**: Create an archive on POSIX with paths
  containing `\..` patterns, attempt to extract on Windows, and verify the
  paths are rejected.

### 5. Pattern Matching

- **Test Windows-style pattern input behavior**: Provide patterns with
  backslashes on Windows and verify the behavior (should be treated as
  literal characters, not separators).
- **Test complex regex patterns**: Verify that complex regex patterns work
  without normalization breaking them.
- **Test pattern matching consistency**: Verify that the same patterns produce
  the same results on Windows and POSIX.

### 7. Cross-Platform Archive Compatibility

- **Test archives created on Windows, extracted on POSIX**: Create an archive
  on Windows, extract on POSIX, and verify all paths are correct.
- **Test archives created on POSIX, extracted on Windows**: Create an archive
  on POSIX (including files with literal backslashes in names), extract on
  Windows, and verify paths are correct (with `%` replacement).
- **Test round-trip compatibility**: Create an archive on one platform,
  extract on another, create a new archive, and verify the contents match.

### 8. Boundary Normalization Timing

- **Test `get_strip_prefix` receives normalized paths**: Verify that
  `get_strip_prefix` only sees paths with `/` on Windows (no `\`).
- **Test `remove_dotdot_prefixes` receives normalized paths**: Verify that
  `remove_dotdot_prefixes` only sees paths with `/` on Windows (no `\`).
- **Test normalization order**: Verify that boundary normalization happens
  before `get_strip_prefix` and `remove_dotdot_prefixes` are called.

### 9. Error Handling and User Feedback

- **Test error messages for modified paths**: Verify that users receive clear
  error messages when paths are modified (e.g., `\` replaced with `%`).
- **Test warnings during extraction**: Verify that appropriate warnings are
  shown when extracting files with replacement characters.
- **Test user-friendly error messages**: Verify that error messages explain
  Windows path limitations clearly.

### 10. Path Normalization (`posixpath.normpath` vs `os.path.normpath`)

- **Test that `posixpath.normpath` is used in all critical code paths**: Verify
  that internal path normalization uses `posixpath.normpath` to maintain the
  forward-slash standard on all platforms.
- **Test pattern matching with normalized paths**: Verify that patterns work
  correctly after normalization with `posixpath.normpath`.
- **Test archive paths contain only forward slashes**: Create archives on
  Windows and verify all stored paths use `/` as separator (no `\`).
- **Test `get_strip_prefix` with forward slashes**: Verify that the slashdot
  hack (`/./`) works correctly and the prefix uses forward slashes.
- **Test path collapsing behavior**: Verify that `../` and `./` are collapsed
  correctly using `posixpath.normpath` on Windows.
- **Regression test**: Ensure no code accidentally reintroduces `os.path.normpath`
  in critical paths (patterns, archive creation, path manipulation).

---

## Section 7: Verification Plan

### Testing Approach

1. **Unit tests**: Add unit tests for all helper functions (`make_path_safe`,
   `to_safe_link_target`, `get_strip_prefix`, `remove_dotdot_prefixes`).
2. **Integration tests**: Add integration tests for archive creation,
   extraction, and pattern matching on Windows.
3. **Cross-platform tests**: Run tests on both Windows and POSIX systems to
   verify cross-platform compatibility.
4. **Manual testing**: Perform manual testing on Windows with real-world
   scenarios (symlinks, hardlinks, complex patterns, etc.).

### Test Environment

- **Primary**: Native Windows environment (Windows 10 or later).
- **Secondary**: Windows Subsystem for Linux (WSL) for cross-platform
  testing, or a simulated Windows environment.

### Success Criteria

- All existing tests pass on Windows.
- All new tests pass on Windows and POSIX.
- Archives created on Windows can be extracted on POSIX and vice versa.
- Symlinks and hardlinks work correctly on Windows.
- Pattern matching works consistently across platforms.
- Security checks prevent directory traversal attacks on all platforms.

---

## Section 8: Implementation Order

### Phase 1: Foundation
1. Implement helper functions in `fs.py` (`make_path_safe`,
   `to_safe_link_target`).
2. Update `Item.path` and `Item.target` encoding/decoding in `item.pyx`.
3. Add security checks for `\..` and `..\` patterns.
4. **Fix `os.path.normpath` → `posixpath.normpath`** in `fs.py`:
   - In `get_strip_prefix()`: Replace `os.path.normpath` with `posixpath.normpath` in the return statement
   - Ensure `remove_dotdot_prefixes()` already uses `posixpath.normpath`

### Phase 2: Boundary Normalization and Path Operations
5. Update `PathSpec` in `parseformat.py`:
   - Apply boundary normalization (`\` → `/`) for filesystem paths on Windows BEFORE calling `posixpath.normpath`
   - Replace `os.path.normpath` with `posixpath.normpath` for both patterns and filesystem paths
   - Replace `os.path.abspath` with boundary normalization + `posixpath.normpath` for filesystem paths
   - Note: Patterns get `posixpath.normpath` only; filesystem paths get boundary normalization first, then `posixpath.normpath`
6. Update `_rec_walk` and `do_create` in `create_cmd.py`:
   - Apply boundary normalization (`\` → `/`) for paths from filesystem walker on Windows
   - Replace `os.path.normpath` with `posixpath.normpath` in both `do_create()` and `_rec_walk()` methods
   - Replace `os.path.join` with `posixpath.join` when joining path components for archive paths (e.g., `path` with `dirent.name`, `path` with `tag_name`)
7. Update `remove_dotdot_prefixes` in `fs.py` (remove redundant backslash normalization).

### Phase 3: Pattern Matching and Archive Operations
8. **Fix `os.path.normpath` → `posixpath.normpath`** in `patterns.py`:
    - All pattern classes: PathFullPattern, PathPrefixPattern, FnmatchPattern, ShellPattern
    - Replace all `os.path.sep` with `"/"` in pattern matching logic
9. Update archive creation and extraction logic to use `/` exclusively.
10. **Fix `os.path.normpath` → `posixpath.normpath`** in `archive.py` tar import functionality (for `tarinfo.name` and `tarinfo.linkname`).
11. Update `Archive.create_helper` to use `/` for path operations.

### Phase 4: Testing and Validation
12. Add unit tests for all changes.
13. Add integration tests for cross-platform compatibility.
14. Add tests to verify `posixpath.normpath` is used instead of `os.path.normpath` in all critical paths.
15. Perform manual testing on Windows

---

## Section 9: Documentation Updates

### User-Facing Documentation

- **Usage guide**: Add notes about Windows path separator handling (forward
  slashes in patterns, backslash normalization).
- **Changelog**: Document path separator handling improvements for Windows.

### Developer Documentation

- **Architecture**: Document the forward-slash standard and boundary
  normalization approach for path separators.
- **Contributing guide**: Add notes about path separator handling
  considerations for contributors.

---

## Section 10: Known Limitations and Future Work

### Known Limitations

1. **Replacement character collisions**: Files with `%` and `\` in names on
   POSIX may collide on Windows.
2. **Windows drive letters**: Handling of drive letters in archive paths is
   deferred.
3. **FUSE support**: FUSE operations on Windows are deferred.

### Future Work

1. **Windows drive letter handling**: Implement proper handling of drive
   letters in archive paths (path separator considerations for absolute
   paths).
2. **FUSE support on Windows**: Implement FUSE operations on Windows with
   proper path separator handling (if feasible).

---

## Conclusion

This plan provides a comprehensive approach to improving Windows compatibility
in Borg Backup. By adopting a forward-slash standard and implementing boundary
normalization, we can simplify internal logic while maintaining cross-platform
archive compatibility. The phased implementation approach ensures that changes
are made incrementally and thoroughly tested.
