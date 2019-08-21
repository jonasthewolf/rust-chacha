use chacha::chacha::{Chacha, Nonce};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_1(b: &mut Criterion) {
    let mykey = vec![
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5,
        0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70,
        0x75, 0xc0,
    ];
    let mynonce: Nonce = [0x00000000, 0x00000000, 0x02000000];
    let mut c = Chacha::new(&mykey, &mynonce);
    let mut keystream = [0u8; 64];
    b.bench_function("chacha20 keystream", move |x| {
        x.iter(|| c.get_keystream(&mut keystream[0..64], 0))
    });
}

criterion_group!(benches, bench_1);
criterion_main!(benches);
