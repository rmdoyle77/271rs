// src/lib.rs
use std::cmp::Ordering;
use std::fmt;

pub struct IntX {
    pub data: Vec<u64>,
}

impl IntX {
    pub fn zero() -> Self {
        IntX { data: vec![0] }
    }

    pub fn from_u64(x: u64) -> Self {
        IntX { data: vec![x] }
    }

    pub fn normalize(&mut self) {
        while self.data.len() > 1 && *self.data.last().unwrap() == 0 {
            self.data.pop();
        }
    }

    pub fn from_hex(s: &str) -> Self {
        let hex = s.strip_prefix("0x").unwrap_or(s);
        let mut out = IntX { data: Vec::new() };
        let mut i = hex.len();
        while i > 0 {
            let start = i.saturating_sub(16);
            let chunk_str = &hex[start..i];
            let chunk_val = u64::from_str_radix(chunk_str, 16).unwrap();
            out.data.push(chunk_val);
            i = start;
        }
        out.normalize();
        out
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::new();
        let mut iter = self.data.iter().rev();
        if let Some(ms) = iter.next() {
            s.push_str(&format!("{:x}", ms));
        } else {
            return "0".to_string();
        }
        for limb in iter {
            s.push_str(&format!("{:016x}", limb));
        }
        s
    }

    fn cmp_abs(&self, other: &Self) -> Ordering {
        if self.data.len() != other.data.len() {
            return self.data.len().cmp(&other.data.len());
        }
        for (&a, &b) in self.data.iter().zip(other.data.iter()).rev() {
            if a != b {
                return a.cmp(&b);
            }
        }
        Ordering::Equal
    }
}

impl fmt::Display for IntX {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

