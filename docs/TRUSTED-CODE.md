# Trusted code: what the count includes

`elastos/trusted-code.json` lists the code the Runtime trusts: the ElastOS-written files that decide
who may do what, the in-process libraries from `elastos/Cargo.lock`, and the host programs of the
signed component set in `components.json`. `scripts/trusted-code.py` prints their numbers as text and
as JSON.

## The count rule

The unit is one line of a listed Rust file. A line is one of four kinds:

- **Code line**: holds at least one Rust token that is not a comment token. A line inside a
  multi-line string literal is code.
- **Blank line**: holds no token.
- **Comment line**: holds only comments, or lies inside a block or doc comment.
- **Test line**: belongs to an item under `#[cfg(test)]`, from the attribute through the item's end;
  belongs to a `#[cfg(test)]` statement, from the attribute through its `;` or closing brace; or
  belongs to a whole test file, whose path has a `tests/` directory.

The count of a file is its code lines. Test, comment and blank lines are excluded. Generated code is
excluded: a listed file that uses `include!` is refused, so generated text cannot enter the count
unnoticed. Each file is counted on its own; `mod name;` pulls no other file's lines into the count,
so the list must name every file that makes a decision.

The third-party entries use the same manifest. A library is an exact `Cargo.lock` package name or a
prefix such as `cranelift-`; a host program is a `components.json` external key. The counter reads
the versions from those files and never records a version of its own.

The core crate's number comes from `scripts/core-size.py`'s own `count()`, so the two reports cannot
disagree.

## Worked examples

**A small file, counted by hand.** Eleven lines:

```rust
fn kept() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn one() {
        assert_eq!(super::kept(), 1);
    }
}
```

Lines 1 to 3 hold code, line 4 is blank, and lines 5 to 11 are the `#[cfg(test)]` module. By hand:
3 code, 7 test, 1 blank. The script prints `{"total": 11, "tests": 7, "comments": 0, "blank": 1,
"code": 3}`.

**`elastos/crates/elastos-runtime/src/capability/store.rs`, counted by hand.** The file has 330 lines.
57 lines hold only comments, 33 are blank, and lines 256 to 330 are the `#[cfg(test)] mod tests`
block, 75 lines. The remaining 165 lines hold code. The script prints `code 165, total 330, tests 75,
comments 57, blank 33`, which matches the hand count.
