//! COM 骨架冒烟测试：加载 DLL → DllGetClassObject → 类工厂 → CreateInstance → 接口调用。

use windows::core::{s, Interface, GUID, PCWSTR};
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Com::IClassFactory;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Shell::{ICredentialProvider, CPUS_UNLOCK_WORKSTATION};

type DllGetClassObjectFn = unsafe extern "system" fn(
    *const GUID,
    *const GUID,
    *mut *mut core::ffi::c_void,
) -> windows::core::HRESULT;

fn load_dll() -> (windows::core::HRESULT, DllGetClassObjectFn) {
    let dll = std::env::current_exe()
        .expect("当前测试路径")
        .parent()
        .unwrap()
        .join("watch_unlock_provider.dll");
    let wide: Vec<u16> = dll
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let h = LoadLibraryW(PCWSTR(wide.as_ptr())).expect("DLL 加载失败");
        let proc = GetProcAddress(h, s!("DllGetClassObject")).expect("DllGetClassObject 导出缺失");
        (
            windows::core::HRESULT(0),
            std::mem::transmute::<unsafe extern "system" fn() -> isize, DllGetClassObjectFn>(proc),
        )
    }
}

#[test]
fn com_skeleton_works() {
    let (_, get_class) = load_dll();
    unsafe {
        // 1. 类工厂
        let mut factory_raw = std::ptr::null_mut();
        let hr = get_class(
            &watch_unlock_provider::CLSID,
            &IClassFactory::IID,
            &mut factory_raw,
        );
        assert_eq!(hr.0, 0, "DllGetClassObject 失败");
        assert!(!factory_raw.is_null());
        let factory = IClassFactory::from_raw(factory_raw);

        // 2. 创建 provider 实例（泛型版本：IID 由目标类型推断）
        let prov: ICredentialProvider = factory.CreateInstance(None).expect("CreateInstance 失败");

        // 3. 无解锁信号时：0 凭据（故障安全，不干扰系统密码框）
        let (mut count, mut default_idx, mut auto) = (0u32, 0u32, BOOL(0));
        prov.GetCredentialCount(&mut count, &mut default_idx, &mut auto)
            .expect("GetCredentialCount 失败");
        assert_eq!(count, 0);

        // 4. usage scenario 冒烟
        prov.SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0)
            .expect("SetUsageScenario 失败");

        // 5. 错误 CLSID 必须返回 CLASS_E_CLASSNOTAVAILABLE
        let mut out = std::ptr::null_mut();
        let bad = get_class(&GUID::zeroed(), &IClassFactory::IID, &mut out);
        assert_ne!(bad.0, 0);
    }
}
