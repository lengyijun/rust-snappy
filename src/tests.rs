use quickcheck::{QuickCheck, StdGen};
#[cfg(feature = "cpp")]
use snappy_cpp as cpp;

use {Decoder, Error, compress, decompress_len, max_compressed_len};

// roundtrip is a macro that compresses the input, then decompresses the result
// and compares it with the original input. If they are not equal, then the
// test fails.
macro_rules! roundtrip {
    ($data:expr) => {
        let d = &$data[..];
        assert_eq!(d, &*depress(&press(d)));
    }
}

// errored is a macro that tries to decompress the input and asserts that it
// resulted in an error. If decompression was successful, then the test fails.
macro_rules! errored {
    ($data:expr) => {
        errored!($data, Error::Corrupt);
    };
    ($data:expr, $err:expr) => {
        let d = &$data[..];
        let mut buf = vec![0; 1024];

        assert_eq!($err, decompress_len(d).unwrap_err());
        match Decoder::new().decompress(d, &mut buf) {
            Err(ref err) if err == &$err => {}
            Err(ref err) => {
                panic!("expected decompression to fail with {:?}, \
                        but got {:?}", $err, err)
            }
            Ok(n) => {
                panic!("\nexpected decompression to fail, but did not!
original (len == {:?})
----------------------
{:?}

decompressed (len == {:?})
--------------------------
{:?}
", d.len(), d, n, buf);
            }
        }
    };
}

// testtrip is a macro that defines a test that compresses the input, then
// decompresses the result and compares it with the original input. If they are
// not equal, then the test fails.
//
// If tests are compiled with the cpp feature, then this also tests that the
// C++ library compresses to the same bytes that the Rust library does.
macro_rules! testtrip {
    ($name:ident, $data:expr) => {
        mod $name {
            #[test]
            fn roundtrip() {
                use super::{depress, press};
                roundtrip!($data);
            }

            #[test]
            #[cfg(feature = "cpp")]
            fn cmpcpp() {
                use super::{press, press_cpp};

                let data = &$data[..];
                let rust = press(data);
                let cpp = press_cpp(data);
                if rust == cpp {
                    return;
                }
                panic!("\ncompression results are not equal!
original (len == {:?})
----------------------
{:?}

rust (len == {:?})
------------------
{:?}

cpp (len == {:?})
-----------------
{:?}
", data.len(), data, rust.len(), rust, cpp.len(), cpp);
            }
        }
    }
}

// testcorrupt is a macro that defines a test that decompresses the input,
// and if the result is anything other than the error given, the test fails.
macro_rules! testerrored {
    ($name:ident, $data:expr) => {
        testerrored!($name, $data, Error::Corrupt);
    };
    ($name:ident, $data:expr, $err:expr) => {
        #[test]
        fn $name() {
            errored!($data, $err);
        }
    };
}

// Simple test cases.
testtrip!(empty, &[]);
testtrip!(one_zero, &[0]);

// Roundtrip all of the benchmark data.
testtrip!(data_html, include_bytes!("../data/html"));
testtrip!(data_urls, include_bytes!("../data/urls.10K"));
testtrip!(data_jpg, include_bytes!("../data/fireworks.jpeg"));
testtrip!(data_pdf, include_bytes!("../data/paper-100k.pdf"));
testtrip!(data_html4, include_bytes!("../data/html_x_4"));
testtrip!(data_txt1, include_bytes!("../data/alice29.txt"));
testtrip!(data_txt2, include_bytes!("../data/asyoulik.txt"));
testtrip!(data_txt3, include_bytes!("../data/lcet10.txt"));
testtrip!(data_txt4, include_bytes!("../data/plrabn12.txt"));
testtrip!(data_pb, include_bytes!("../data/geo.protodata"));
testtrip!(data_gaviota, include_bytes!("../data/kppkn.gtb"));
testtrip!(data_golden, include_bytes!("../data/Mark.Twain-Tom.Sawyer.txt"));

// Roundtrip the golden data, starting with the compressed bytes.
#[test]
fn data_golden_rev() {
    let data = include_bytes!("../data/Mark.Twain-Tom.Sawyer.txt.rawsnappy");
    let data = &data[..];
    assert_eq!(data, &*press(&depress(data)));
}

// Miscellaneous tests.
#[test]
fn small_copy() {
    use std::iter::repeat;

    for i in 0..32 {
        let inner: String = repeat('b').take(i).collect();
        roundtrip!(format!("aaaa{}aaaabbbb", inner).into_bytes());
    }
}

#[test]
fn small_regular() {
    let mut i = 1;
    while i < 20_000 {
        let mut buf = vec![0; i];
        for (j, x) in buf.iter_mut().enumerate() {
            *x = (j % 10) as u8 + b'a';
        }
        roundtrip!(buf);
        i += 23;
    }
}

// Tests decompression on malformed data.
testerrored!(err_varint1, &b"\xFF"[..]);
testerrored!(err_varint2,
             &b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00"[..]);
testerrored!(err_varint3, &b"\x80\x80\x80\x80\x10"[..],
             Error::TooBig {
                 given: 4294967296,
                 max: 4294967295,
             });

// Selected random inputs pulled from quickcheck failure witnesses.
testtrip!(random1, &[
    0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 1, 1,
    0, 0, 1, 2, 0, 0, 2, 1, 0, 0, 2, 2, 0, 0, 0, 6, 0, 0, 3, 1, 0, 0, 0, 7, 0,
    0, 1, 3, 0, 0, 0, 8, 0, 0, 2, 3, 0, 0, 0, 9, 0, 0, 1, 4, 0, 0, 1, 0, 0, 3,
    0, 0, 1, 0, 1, 0, 0, 0, 10, 0, 0, 0, 0, 2, 4, 0, 0, 2, 0, 0, 3, 0, 1, 0, 0,
    1, 5, 0, 0, 6, 0, 0, 0, 0, 11, 0, 0, 1, 6, 0, 0, 1, 7, 0, 0, 0, 12, 0, 0,
    3, 2, 0, 0, 0, 13, 0, 0, 2, 5, 0, 0, 0, 3, 3, 0, 0, 0, 1, 8, 0, 0, 1, 0,
    1, 0, 0, 0, 4, 1, 0, 0, 0, 0, 14, 0, 0, 0, 1, 9, 0, 0, 0, 1, 10, 0, 0, 0,
    0, 1, 11, 0, 0, 0, 1, 0, 2, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 5, 1, 0, 0, 0, 1,
    2, 1, 0, 0, 0, 0, 0, 2, 6, 0, 0, 0, 0, 0, 1, 12, 0, 0, 0, 0, 0, 3, 4, 0, 0,
    0, 0, 0, 7, 0, 0, 0, 0, 0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
testtrip!(random2, &[
    10, 2, 14, 13, 0, 8, 2, 10, 2, 14, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
testtrip!(random3, &[
    0, 0, 0, 4, 1, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
testtrip!(random4, &[
    0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 1, 1,
    0, 0, 1, 2, 0, 0, 1, 3, 0, 0, 1, 4, 0, 0, 2, 1, 0, 0, 0, 4, 0, 1, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
]);

// QuickCheck properties for testing that random data roundtrips.
// These properties tend to produce the inputs for the "random" tests above.

#[test]
fn qc_roundtrip() {
    fn p(bytes: Vec<u8>) -> bool {
        depress(&press(&bytes)) == bytes
    }
    QuickCheck::new()
        .gen(StdGen::new(::rand::thread_rng(), 10_000))
        .tests(1_000)
        .quickcheck(p as fn(_) -> _);
}

#[test]
#[cfg(feature = "cpp")]
fn qc_cmpcpp() {
    fn p(bytes: Vec<u8>) -> bool {
        press(&bytes) == press_cpp(&bytes)
    }
    QuickCheck::new()
        .gen(StdGen::new(::rand::thread_rng(), 10_000))
        .tests(1_000)
        .quickcheck(p as fn(_) -> _);
}

// Helper functions.

fn press(bytes: &[u8]) -> Vec<u8> {
    let mut buf = vec![0; max_compressed_len(bytes.len())];
    let n = compress(bytes, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn depress(bytes: &[u8]) -> Vec<u8> {
    Decoder::new().decompress_vec(bytes).unwrap()
}

#[cfg(feature = "cpp")]
fn press_cpp(bytes: &[u8]) -> Vec<u8> {
    let mut buf = vec![0; max_compressed_len(bytes.len())];
    let n = cpp::compress(bytes, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

#[cfg(feature = "cpp")]
fn depress_cpp(bytes: &[u8]) -> Vec<u8> {
    let mut buf = vec![0; decompress_len(bytes).unwrap()];
    let m = cpp::decompress(bytes, &mut buf).unwrap();
    buf
}