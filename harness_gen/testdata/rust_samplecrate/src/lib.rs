/// Crate Rust real y minimo, local (no clonado de red) -- fixture para
/// testear generate_rust_harness.py sin depender de la red ni de un
/// crate externo.
pub fn parse_len_prefixed(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    let len = data[0] as usize;
    data.get(1..1 + len)
}
