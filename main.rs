extern crate secp256k1;
extern crate rand;
extern crate tiny_keccak;

use secp256k1::Secp256k1;
use rand::thread_rng;
use tiny_keccak::Keccak;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};
use std::io;

fn generate_key_address(rng: &mut impl rand::Rng, context: &Secp256k1) -> (String, String) {
    let (private_key, public_key) = context.generate_keypair(rng)
        .expect("Could not generate wallet keypair");

    let mut sha3 = Keccak::new_keccak256();
    sha3.update(&public_key.serialize_uncompressed()[1..65]);

    let mut address: [u8; 32] = [0; 32];
    sha3.finalize(&mut address);

    let address_string: String = address.iter().skip(12)
        .map(|byte| format!("{:02x}", byte))
        .collect();

    let private_key_string: String = private_key[..].iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();

    (private_key_string, address_string)
}

fn find_address_starting_with(found: Arc<AtomicBool>, processed: Arc<AtomicU64>, x: &String)
    -> (String, String)
{
    let mut rng = thread_rng();
    let context = Secp256k1::new();

    loop {
        if found.load(Ordering::Relaxed) {
            return (String::new(), String::new());
        }

        let (pkey, address) = generate_key_address(&mut rng, &context);
        if address.starts_with(x) {
            found.store(true, Ordering::Relaxed);
            return (pkey, address);
        }
        processed.fetch_add(1, Ordering::Relaxed);
    }
}

fn main() {
    println!("Enter starting line for an address:");

    let mut pattern = String::new();
    io::stdin().read_line(&mut pattern).expect("Could not read pattern from stdin");
    pattern = pattern.trim().to_string();

    if pattern.chars().any(|c| !c.is_digit(16)) {
        println!("Invalid pattern. Use 0-9, a-f.");
        return;
    }

    println!("Generating...");

    let found = Arc::new(AtomicBool::new(false));
    let processed = Arc::new(AtomicU64::new(0));
    let (tx, rx): (Sender<(String, String)>, Receiver<(String, String)>) = channel();

    let thread_count = 8;
    let mut threads = vec![];

    for _ in 0..thread_count {
        let found_clone = Arc::clone(&found);
        let processed_clone = Arc::clone(&processed);
        let pattern_clone = pattern.clone();
        let thread_tx = tx.clone();

        threads.push(thread::spawn(move || {
            let result = find_address_starting_with(found_clone, processed_clone, &pattern_clone);
            thread_tx.send(result).expect("Could not send result");
        }));
    }

    let start_time = Instant::now();

    loop {
        if let Ok((pkey, address)) = rx.recv_timeout(Duration::from_millis(1000)) {
            println!("Private key: {}", pkey);
            println!("Address: 0x{}", address);
            break;
        }

        let elapsed = start_time.elapsed().as_secs();
        let processed_addresses = processed.load(Ordering::Relaxed);
        let speed = if elapsed > 0 {
            processed_addresses / elapsed
        } else {
            0
        };

        // Safely calculate difficulty to prevent overflow
        let difficulty = match 16u64.checked_pow(pattern.len() as u32) {
            Some(d) => d,
            None => {
                println!("Difficulty calculation overflowed.");
                u64::MAX
            },
        };

        let estimated_time = if speed > 0 {
            match difficulty.checked_div(speed) {
                Some(t) => t,
                None => u64::MAX,
            }
        } else {
            u64::MAX
        };

        println!("Speed: {} h/s. Work time: {}s. Estimated time: {}s",
                 speed, elapsed, estimated_time);
    }

    found.store(true, Ordering::Relaxed);

    for t in threads {
        let _ = t.join();
    }

    println!("Completed.");
}
