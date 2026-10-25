# Microsoft WebView2 loader

The distributed x64 `WebView2Loader.dll` is Microsoft SDK code, separate from the Rust wrapper's MIT license. Its file version is `1.0.3800.47`. The DLL from the locked `webview2-com-sys` 0.39.1 crate is byte-for-byte identical to `build/native/x64/WebView2Loader.dll` in the official `Microsoft.Web.WebView2` 1.0.3800.47 NuGet package: 160,880 bytes, SHA256 `86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5`.

The version directory reproduces the NuGet package's complete `LICENSE.txt` and `NOTICE.txt` without modification. Its package metadata declares the license as that file; the text includes Microsoft's copyright, redistribution conditions, disclaimer, and the accompanying third-party notices. `provenance.json` records the exact public package URL, archive checksum, DLL checksum, and notice checksums without local paths.

This record covers the loader included in this application package. It does not inventory the separately installed Microsoft Edge WebView2 Runtime. If the loader changes, verify its exact SDK package and refresh these materials before distribution.
