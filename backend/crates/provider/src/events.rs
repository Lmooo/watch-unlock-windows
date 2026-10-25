//! Apartment-safe event registration. Only a GIT cookie crosses threads.

use std::sync::Mutex;

use windows::core::{Interface, GUID};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IGlobalInterfaceTable,
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::UI::Shell::ICredentialProviderEvents;

const GLOBAL_INTERFACE_TABLE: GUID = GUID::from_u128(0x00000323_0000_0000_c000_000000000046);

pub struct Apartment;

impl Apartment {
    pub fn new() -> windows::core::Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()?; }
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize(); }
    }
}

fn table() -> windows::core::Result<IGlobalInterfaceTable> {
    unsafe { CoCreateInstance(&GLOBAL_INTERFACE_TABLE, None, CLSCTX_INPROC_SERVER) }
}

struct Registration {
    cookie: u32,
    context: usize,
}

#[derive(Default)]
pub struct Events(Mutex<Option<Registration>>);

impl Events {
    /// Called in the apartment that owns the supplied event interface.
    pub fn advise(&self, event: Option<&ICredentialProviderEvents>, context: usize)
        -> windows::core::Result<()>
    {
        let git = table()?;
        let next = match event {
            Some(event) => Some(Registration {
                cookie: unsafe { git.RegisterInterfaceInGlobal(event, &ICredentialProviderEvents::IID)? },
                context,
            }),
            None => None,
        };
        let mut current = crate::lock_ok(&self.0);
        if let Some(previous) = current.take() {
            unsafe { let _ = git.RevokeInterfaceFromGlobal(previous.cookie); }
        }
        *current = next;
        Ok(())
    }

    /// Serialize revoke with GetInterfaceFromGlobal, as required by COM.
    pub fn unadvise(&self) {
        let mut current = crate::lock_ok(&self.0);
        if let Some(previous) = current.take() {
            if let Ok(git) = table() {
                unsafe { let _ = git.RevokeInterfaceFromGlobal(previous.cookie); }
            }
        }
    }

    pub fn notify(&self) {
        let resolved = (|| -> windows::core::Result<Option<(ICredentialProviderEvents, usize)>> {
            let current = crate::lock_ok(&self.0);
            let Some(registration) = current.as_ref() else { return Ok(None); };
            let mut raw = std::ptr::null_mut();
            unsafe {
                table()?.GetInterfaceFromGlobal(registration.cookie, &ICredentialProviderEvents::IID, &mut raw)?;
                Ok(Some((ICredentialProviderEvents::from_raw(raw), registration.context)))
            }
        })();
        // A callback may reenter provider methods. Never hold state or GIT locks here.
        if let Ok(Some((event, context))) = resolved {
            unsafe { let _ = event.CredentialsChanged(context); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
    use std::os::windows::io::AsRawHandle;
    use windows::core::{implement, ComObject};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Com::{CoWaitForMultipleHandles, COINIT_APARTMENTTHREADED,
        COWAIT_DISPATCH_CALLS, COWAIT_DISPATCH_WINDOW_MESSAGES};
    use windows::Win32::UI::Shell::ICredentialProviderEvents_Impl;

    #[implement(ICredentialProviderEvents)]
    struct Receiver { calls: Arc<AtomicUsize> }

    impl ICredentialProviderEvents_Impl for Receiver_Impl {
        fn CredentialsChanged(&self, context: usize) -> windows::core::Result<()> {
            assert_eq!(context, 42);
            self.calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    #[test]
    fn event_is_marshaled_and_revocation_stops_future_notifications() {
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok() }.unwrap();
        let _apartment = Apartment;
        let calls = Arc::new(AtomicUsize::new(0));
        let receiver: ICredentialProviderEvents =
            ComObject::new(Receiver { calls: calls.clone() }).to_interface();
        let events = Arc::new(Events::default());
        events.advise(Some(&receiver), 42).unwrap();
        let worker_events = events.clone();
        let worker = std::thread::spawn(move || {
            let _apartment = Apartment::new().unwrap();
            worker_events.notify();
        });
        // Pump STA COM calls while the MTA worker invokes the marshaled event.
        unsafe {
            CoWaitForMultipleHandles((COWAIT_DISPATCH_CALLS | COWAIT_DISPATCH_WINDOW_MESSAGES).0 as u32,
                5000, &[HANDLE(worker.as_raw_handle())]).unwrap();
        }
        worker.join().unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        events.unadvise();
        events.notify();
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }
}
