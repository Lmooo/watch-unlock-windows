; Installer hooks for the setup.exe built by `tauri build`. NSIS is a 32-bit program, so every
; registry write uses SetRegView 64; otherwise the provider would land in WOW6432Node and LogonUI
; (64-bit) would never load it.

!define WU_CLSID "{A8CA66E1-5FCA-45DD-8D79-44FC9701B739}"
!define WU_PROVIDER_KEY "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\${WU_CLSID}"
!define WU_CLASS_KEY "SOFTWARE\Classes\CLSID\${WU_CLSID}"
!define WU_RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"

!macro WU_STOP_BACKGROUND
  ; The supervisor first, so it cannot relaunch the daemon being replaced.
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM watchd-supervisor.exe'
  Pop $0
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM watchd.exe'
  Pop $0
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; The login component runs as SYSTEM and the background holds the account password, so both
  ; must live where only administrators can write: Program Files. The provider refuses a
  ; background anywhere else, so stop here instead of installing a copy that cannot unlock.
  StrLen $1 "$PROGRAMFILES64\"
  StrCpy $2 "$INSTDIR" $1
  ${If} $2 != "$PROGRAMFILES64\"
    RMDir "$INSTDIR"
    MessageBox MB_ICONSTOP|MB_OK "Watch Unlock 必须安装在“$PROGRAMFILES64”下的文件夹中。$\r$\n$\r$\n登录组件以系统权限运行，后台保存着账户密码，只有放在仅管理员可修改的目录里才安全。$\r$\n请重新运行安装程序，使用默认目录，或选择 Program Files 下的其他文件夹。" /SD IDOK
    Abort
  ${EndIf}
  !insertmacro WU_STOP_BACKGROUND
  ; LogonUI keeps the provider DLL loaded, so it cannot be overwritten. A loaded DLL can still be
  ; renamed; the old copy is removed at the next restart.
  ${If} ${FileExists} "$INSTDIR\watch_unlock_provider.dll"
    Delete "$INSTDIR\watch_unlock_provider.dll.old"
    Rename "$INSTDIR\watch_unlock_provider.dll" "$INSTDIR\watch_unlock_provider.dll.old"
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  Delete /REBOOTOK "$INSTDIR\watch_unlock_provider.dll.old"
  SetRegView 64
  WriteRegStr HKLM "${WU_PROVIDER_KEY}" "" "Watch Unlock Windows"
  WriteRegStr HKLM "${WU_CLASS_KEY}\InprocServer32" "" "$INSTDIR\watch_unlock_provider.dll"
  WriteRegStr HKLM "${WU_CLASS_KEY}\InprocServer32" "ThreadingModel" "Apartment"
  ; Start the background at logon for the installing user; the app's switch turns it off.
  WriteRegStr HKCU "${WU_RUN_KEY}" "WatchUnlockWindows" '"$INSTDIR\watchd-supervisor.exe"'
  SetRegView 32
  ; Earlier script-based installs used a scheduled task of the same name.
  nsExec::Exec '"$SYSDIR\schtasks.exe" /Delete /TN WatchUnlockWindows /F'
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro WU_STOP_BACKGROUND
  SetRegView 64
  DeleteRegKey HKLM "${WU_PROVIDER_KEY}"
  DeleteRegKey HKLM "${WU_CLASS_KEY}"
  DeleteRegValue HKCU "${WU_RUN_KEY}" "WatchUnlockWindows"
  SetRegView 32
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; "Delete application data" also removes the encrypted password, watch keys and history,
  ; which live outside the bundle-id folders the default uninstaller clears. Kept on updates.
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    SetShellVarContext current
    RMDir /r "$LOCALAPPDATA\WatchUnlockWindows"
  ${EndIf}
!macroend
