//! `render seed <hex>`         print traits + matrix hash for one seed
//! `render check <vectors.json>` compare against reference vectors (seed, hash, traits)
//! `render sin`                 print the frozen sine table hash

use overstory_render::{Traits, grid_hash, render, sin_table_sha256};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("seed") => {
            let seed: [u8; 32] = hex::decode(&args[1]).expect("hex").try_into().expect("32 bytes");
            let (g, t) = render(&seed);
            println!("{}", serde_json::json!({"seed": args[1], "traits": t, "matrix_sha256": grid_hash(&g)}));
        }
        Some("check") => {
            #[derive(serde::Deserialize)]
            struct V {
                seed: String,
                hash: String,
                traits: Traits,
            }
            let vectors: Vec<V> = serde_json::from_str(&std::fs::read_to_string(&args[1]).expect("read")).expect("json");
            let mut bad = 0;
            for v in &vectors {
                let seed: [u8; 32] = hex::decode(&v.seed).unwrap().try_into().unwrap();
                let (g, t) = render(&seed);
                let h = grid_hash(&g);
                if h != v.hash || t != v.traits {
                    bad += 1;
                    if bad <= 5 {
                        println!("MISMATCH seed={} expected {} got {} traits_equal={}", v.seed, &v.hash[..16], &h[..16], t == v.traits);
                    }
                }
            }
            println!("{} vectors, {} mismatches", vectors.len(), bad);
            if bad > 0 {
                std::process::exit(1);
            }
        }
        Some("sin") => println!("{}", sin_table_sha256()),
        _ => eprintln!("usage: render seed <hex> | check <vectors.json> | sin"),
    }
}
