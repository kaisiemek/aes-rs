#[cfg(test)]
mod test {
    use crate::gf256::{gf256_inv, gf256_mult};

    #[test]
    fn test_gf256_mult() {
        struct TestCase {
            a: u8,
            b: u8,
            expected: u8,
        }

        let test_cases = vec![
            TestCase {
                a: 0x53,
                b: 0xCA,
                expected: 0x01,
            },
            TestCase {
                a: 0xCA,
                b: 0x53,
                expected: 0x01,
            },
            TestCase {
                a: 0x02,
                b: 0x87,
                expected: 0x15,
            },
            TestCase {
                a: 0xFF,
                b: 0xFF,
                expected: 0x13,
            },
            TestCase {
                a: 0xAB,
                b: 0x00,
                expected: 0x00,
            },
            TestCase {
                a: 0xAB,
                b: 0x01,
                expected: 0xAB,
            },
            TestCase {
                a: 0x01,
                b: 0xAB,
                expected: 0xAB,
            },
            TestCase {
                a: 0x12,
                b: 0x34,
                expected: 0x05,
            },
            TestCase {
                a: 0xA0,
                b: 0x24,
                expected: 0x71,
            },
        ];

        for test_case in test_cases {
            assert_eq!(gf256_mult(test_case.a, test_case.b), test_case.expected);
        }
    }

    #[test]
    fn test_gf256_inv() {
        for a in 1..=255 {
            let inverse = gf256_inv(a);
            assert_eq!(gf256_mult(a, inverse), 0x01);
        }
    }
}
