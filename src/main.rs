
mod set_1;

fn main() {
    println!("Hello, world!");

    for i in (0..5).step_by(3) {
        println!("{}", i);
        println!("{}", i + 1 < 5);
        println!("{}", i + 2 < 5);
    }

    let x: u8 = 255;
    println!("num: {:#010b}", x);
    println!("num: {:#010b}", x >> 2);
    println!("num: {:#010b}", x << 6);
    println!("num: {:#010b}", x << 4);
    println!("num: {:#010b}", x >> 4);
}
