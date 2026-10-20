//! Process-wide RPC admission pacing. Never retries a broadcast or changes signed bytes.
use anyhow::{Context,Result};
use std::{sync::{Mutex,OnceLock},time::{Duration,Instant}};
fn rate(setting: Option<&str>, regtest: bool) -> Result<u32> {
    let value=match setting {Some(v)=>v.parse::<u32>().context("OVERSTORY_RPC_RPS must be an integer")?,None=>if regtest {0}else{8}};
    anyhow::ensure!((1..=1000).contains(&value) || (value==0 && regtest),"OVERSTORY_RPC_RPS must be 1..1000 (0 is allowed only on Regtest)");
    Ok(value)
}
struct Pacer { next: Instant }
impl Pacer {
    fn admit(&mut self, per_second:u32) {
        let now=Instant::now();
        if self.next>now {std::thread::sleep(self.next-now);}
        self.next=Instant::now()+Duration::from_nanos(1_000_000_000/u64::from(per_second));
    }
}
pub(crate) fn wait(regtest:bool) -> Result<()> {
    let setting=std::env::var("OVERSTORY_RPC_RPS").ok();
    let rps=rate(setting.as_deref(),regtest)?;
    if rps==0 {return Ok(());}
    static PACER:OnceLock<Mutex<Pacer>>=OnceLock::new();
    PACER.get_or_init(||Mutex::new(Pacer{next:Instant::now()})).lock().unwrap().admit(rps);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_defaults_are_bounded_and_invalid_settings_fail_closed() {
        assert_eq!(rate(None,false).unwrap(),8);assert_eq!(rate(None,true).unwrap(),0);
        for value in ["0","-1","1.5","1001","", "eight"] {assert!(rate(Some(value),false).is_err());}
        assert_eq!(rate(Some("8"),true).unwrap(),8);
    }
    #[test]
    fn concurrent_callers_share_one_schedule_without_accumulating_idle_credit() {
        let pacer=Mutex::new(Pacer{next:Instant::now()-Duration::from_secs(10)});let observations=Mutex::new(Vec::new());
        std::thread::scope(|scope|for _ in 0..8 {scope.spawn(||{let mut guard=pacer.lock().unwrap();guard.admit(100);observations.lock().unwrap().push(Instant::now());});});
        let observed=observations.into_inner().unwrap();
        assert!(observed.windows(2).all(|pair|pair[1].duration_since(pair[0])>=Duration::from_millis(9)));
    }
}
