//! Deployment-owned recovery decisions. The management process is the authority.
//! Crash policies can request a cold restart of an approved generation. Physical
//! safety evidence and operator approval arrive on distinct trusted control paths.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum State {
    Stopped,
    Observing,
    Faulted,
    Moving,
}
#[derive(Debug)]
pub struct Instance {
    pub state: State,
    generation: u64,
    restart_authorized: bool,
    safe_epoch: Option<u64>,
}
impl Instance {
    pub fn new(restart_authorized: bool) -> Self {
        Self {
            state: State::Stopped,
            generation: 0,
            restart_authorized,
            safe_epoch: None,
        }
    }
    pub fn operator_start(&mut self) -> Option<u64> {
        if self.state != State::Stopped {
            return None;
        }
        self.cold_start()
    }
    fn cold_start(&mut self) -> Option<u64> {
        self.generation = self.generation.checked_add(1)?;
        self.safe_epoch = None;
        self.state = State::Observing;
        Some(self.generation)
    }
    pub fn fault(&mut self, generation: u64) -> bool {
        if generation != self.generation || !matches!(self.state, State::Observing | State::Moving)
        {
            return false;
        }
        self.safe_epoch = None;
        self.state = State::Faulted;
        true
    }
    pub fn recover(&mut self, generation: u64) -> Option<u64> {
        if !self.restart_authorized || generation != self.generation || self.state != State::Faulted
        {
            return None;
        }
        self.cold_start()
    }
    pub fn safety_feedback(&mut self, generation: u64, confirmed: bool) {
        if generation != self.generation {
            return;
        }
        self.safe_epoch = if confirmed && self.state == State::Observing {
            Some(generation)
        } else {
            None
        };
        if !confirmed && self.state == State::Moving {
            self.state = State::Faulted
        }
    }
    pub fn operator_enable_motion(&mut self, generation: u64) -> bool {
        if self.state != State::Observing
            || self.safe_epoch != Some(generation)
            || generation != self.generation
        {
            return false;
        }
        self.safe_epoch = None;
        self.state = State::Moving;
        true
    }
    pub fn operator_stop(&mut self) {
        self.safe_epoch = None;
        self.state = State::Stopped;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_requires_grant_and_current_fault() {
        for authorized in [false, true] {
            let mut x = Instance::new(authorized);
            let g = x.operator_start().unwrap();
            assert!(x.fault(g));
            assert_eq!(x.recover(g), authorized.then_some(g + 1));
            assert_eq!(x.recover(g), None);
        }
    }
    #[test]
    fn motion_demands_both_confirmations_for_this_generation() {
        let mut x = Instance::new(true);
        let g = x.operator_start().unwrap();
        assert!(!x.operator_enable_motion(g));
        x.safety_feedback(g, true);
        assert!(x.operator_enable_motion(g));
        x.safety_feedback(g, false);
        let next = x.recover(g).unwrap();
        x.safety_feedback(g, true);
        assert!(!x.operator_enable_motion(next));
        x.safety_feedback(next, true);
        assert!(x.operator_enable_motion(next));
        x.operator_stop();
        assert!(!x.fault(next));
        assert_eq!(x.recover(next), None);
    }
}
