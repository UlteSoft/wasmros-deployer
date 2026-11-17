//! Bounded Linux CPU/NUMA lists. Configuration describes allowed sets, not CPU
//! reservation, real-time scheduling, or a guarantee of memory access latency.
//! Ranges are normalized before comparing requested and effective kernel sets.
use crate::manifest::Result;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Set(Vec<(u32, u32)>);
impl Set {
    pub fn parse(text: &str) -> Result<Self> {
        if text.is_empty() || text.len() > 4096 {
            return Err("CPU/NUMA list must contain 1 to 4096 bytes".into());
        }
        let number = |s: &str| -> Result<u32> {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit())
                || s.len() > 1 && s.starts_with('0')
            {
                return Err("invalid CPU/NUMA index".into());
            }
            s.parse::<u32>().ok().filter(|n| *n < 8192)
                .ok_or_else(|| "CPU/NUMA index must be below 8192".into())
        };
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for part in text.split(',') {
            let (first, last) = match part.split_once('-') {
                Some((a, b)) => (number(a)?, number(b)?),
                None => { let n = number(part)?; (n, n) }
            };
            if first > last {
                return Err("reversed CPU/NUMA range".into());
            }
            if let Some(previous) = ranges.last_mut() {
                if first <= previous.1 {
                    return Err("CPU/NUMA ranges must be ordered and disjoint".into());
                }
                if first == previous.1 + 1 {
                    previous.1 = last;
                    continue;
                }
            }
            ranges.push((first, last));
        }
        Ok(Self(ranges))
    }
    pub fn contains(&self, requested: &Self) -> bool {
        requested.0.iter().all(|(first, last)| self.0.iter()
            .any(|(a, b)| a <= first && last <= b))
    }
    /// Construct outside pre_exec; the child only borrows these native words.
    /// Linux sched_setaffinity accepts a dynamically sized unsigned-long mask.
    pub fn affinity(&self) -> Vec<libc::c_ulong> {
        let bits = libc::c_ulong::BITS as usize;
        let mut words = vec![0; self.0.last().unwrap().1 as usize / bits + 1];
        for (first, last) in &self.0 {
            for cpu in *first..=*last {
                words[cpu as usize / bits] |= 1 << (cpu as usize % bits);
            }
        }
        words
    }
}
impl fmt::Display for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (first, last)) in self.0.iter().enumerate() {
            if i != 0 { write!(f, ",")?; }
            write!(f, "{first}")?;
            if first != last { write!(f, "-{last}")?; }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lists_are_bounded_and_normalized() {
        for invalid in ["", "-1", "1-", "1-0", "1,1", "0-2,2-4", "2,1", " 1", "1,", "01", "8192", "1-2-3", "+1"] {
            assert!(Set::parse(invalid).is_err(), "{invalid}");
        }
        assert!(Set::parse(&"1".repeat(4097)).is_err());
        assert_eq!(Set::parse("0,1-2,5-5,6,8").unwrap().to_string(), "0-2,5-6,8");
    }
    #[test]
    fn membership_respects_holes_and_word_boundaries() {
        let allowed = Set::parse("0-63,65,4095,8191").unwrap();
        assert!(allowed.contains(&Set::parse("31-33,4095,8191").unwrap()));
        assert!(!allowed.contains(&Set::parse("63-65").unwrap()));
        let mask = allowed.affinity();
        let width = libc::c_ulong::BITS as usize;
        for bit in 0..8192 {
            assert_eq!((mask[bit / width] >> (bit % width)) & 1 != 0,
                       bit < 64 || [65, 4095, 8191].contains(&bit));
        }
    }
}
