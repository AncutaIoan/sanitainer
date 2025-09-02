/// Shannon entropy in bits/char.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        freq[b as usize] += 1;
        total += 1;
    }
    let mut h = 0.0;
    for &f in &freq {
        if f == 0 { continue; }
        let p = (f as f64) / (total as f64);
        h -= p * p.log2();
    }
    h
}
