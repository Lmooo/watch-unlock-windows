//! Pure, per-device policy. Adapters must validate the origin and freshness of signals.

mod presence;

pub use presence::{
    Decision, DevicePolicy, DeviceState, Observation, PolicyError, Presence, Session, Transition,
};
