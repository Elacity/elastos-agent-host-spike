//! Static stand-in that writes nothing. Launch accepts it only because
//! `/proc/<provider pid>/exe` matches this binary (device and inode).

extern "C" {
    fn pause() -> i32;
}

fn main() {
    unsafe {
        pause();
    }
}
