mod gf256;

fn main() {
    let mut a: u8 = 0xFF;
    a >>= 1;
    println!("{:#04X}", a);
}
