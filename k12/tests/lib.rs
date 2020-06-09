use core::iter;
use k12::{
    digest::{ExtendableOutput, Update},
    KangarooTwelve,
};

fn read_bytes<T: AsRef<[u8]>>(s: T) -> Box<[u8]> {
    fn b(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => unreachable!(),
        }
    }

    let s = s.as_ref();
    let mut i = 0;
    let mut v = Vec::new();

    while i < s.len() {
        if s[i] == b' ' || s[i] == b'\n' {
            i += 1;
            continue;
        }

        let n = b(s[i]) * 16 + b(s[i + 1]);
        v.push(n);
        i += 2;
    }

    v.into_boxed_slice()
}

#[test]
fn empty() {
    // Source: reference paper
    assert_eq!(
        KangarooTwelve::new().chain(b"").finalize_boxed(32),
        read_bytes(
            "1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca
                1b 37 51 3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5"
        )
    );

    assert_eq!(
        KangarooTwelve::new().chain(b"").finalize_boxed(64),
        read_bytes(
            "1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca
                1b 37 51 3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5 42 69 c0 56 b8 c8 2e
                48 27 60 38 b6 d2 92 96 6c c0 7a 3d 46 45 27 2e 31 ff 38 50 81 39 eb 0a 71"
        )
    );

    assert_eq!(
        KangarooTwelve::new().chain(b"").finalize_boxed(10032)[10000..],
        read_bytes(
            "e8 dc 56 36 42 f7 22 8c 84
                68 4c 89 84 05 d3 a8 34 79 91 58 c0 79 b1 28 80 27 7a 1d 28 e2 ff 6d"
        )[..]
    );
}

#[test]
fn pat_m() {
    let expected = [
        "2b da 92 45 0e 8b 14 7f 8a 7c b6 29 e7 84 a0 58 ef ca 7c f7
                d8 21 8e 02 d3 45 df aa 65 24 4a 1f",
        "6b f7 5f a2 23 91 98 db 47 72 e3 64 78 f8 e1 9b 0f 37 12 05
                f6 a9 a9 3a 27 3f 51 df 37 12 28 88",
        "0c 31 5e bc de db f6 14 26 de 7d cf 8f b7 25 d1 e7 46 75 d7
                f5 32 7a 50 67 f3 67 b1 08 ec b6 7c",
        "cb 55 2e 2e c7 7d 99 10 70 1d 57 8b 45 7d df 77 2c 12 e3 22
                e4 ee 7f e4 17 f9 2c 75 8f 0d 59 d0",
        "87 01 04 5e 22 20 53 45 ff 4d da 05 55 5c bb 5c 3a f1 a7 71
                c2 b8 9b ae f3 7d b4 3d 99 98 b9 fe",
        "84 4d 61 09 33 b1 b9 96 3c bd eb 5a e3 b6 b0 5c c7 cb d6 7c
                ee df 88 3e b6 78 a0 a8 e0 37 16 82",
        "3c 39 07 82 a8 a4 e8 9f a6 36 7f 72 fe aa f1 32 55 c8 d9 58
                78 48 1d 3c d8 ce 85 f5 8e 88 0a f8",
    ];
    for i in 0..5
    /*NOTE: can be up to 7 but is slow*/
    {
        let len = 17usize.pow(i);
        let m: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let result = KangarooTwelve::new().chain(&m).finalize_boxed(32);
        assert_eq!(result, read_bytes(expected[i as usize]));
    }
}

#[test]
fn pat_c() {
    let expected = [
        "fa b6 58 db 63 e9 4a 24 61 88 bf 7a f6 9a 13 30 45 f4 6e e9
                84 c5 6e 3c 33 28 ca af 1a a1 a5 83",
        "d8 48 c5 06 8c ed 73 6f 44 62 15 9b 98 67 fd 4c 20 b8 08 ac
                c3 d5 bc 48 e0 b0 6b a0 a3 76 2e c4",
        "c3 89 e5 00 9a e5 71 20 85 4c 2e 8c 64 67 0a c0 13 58 cf 4c
                1b af 89 44 7a 72 42 34 dc 7c ed 74",
        "75 d2 f8 6a 2e 64 45 66 72 6b 4f bc fc 56 57 b9 db cf 07 0c
                7b 0d ca 06 45 0a b2 91 d7 44 3b cf",
    ];
    for i in 0..4 {
        let m: Vec<u8> = iter::repeat(0xFF).take(2usize.pow(i) - 1).collect();
        let len = 41usize.pow(i);
        let c: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let result = KangarooTwelve::new_with_customization(c)
            .chain(&m)
            .finalize_boxed(32);
        assert_eq!(result, read_bytes(expected[i as usize]));
    }
}
