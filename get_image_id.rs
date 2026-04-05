use risc0_zkvm::compute_image_id;
use std::fs;

fn main() {
    let elf = fs::read("zkvm/target/riscv32im-risc0-zkvm-elf/release/proof-of-claw-guest").unwrap();
    let image_id = compute_image_id(&elf).unwrap();
    println!("0x{}", hex::encode(image_id.as_bytes()));
}
