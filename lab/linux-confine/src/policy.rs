/// Standing network denial. The falsifier in `falsify.py` changes `true` to
/// `false`. With the denial removed, `socket` succeeds and
/// `did_profile_permits_its_operations_and_refuses_the_rest` fails.
pub const DENY_SOCKET: bool = true;

pub fn deny_network_by_default() -> bool {
    DENY_SOCKET
}
