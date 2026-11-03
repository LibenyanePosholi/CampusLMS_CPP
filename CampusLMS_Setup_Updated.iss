; Campus LMS - per-user Windows installer
; The application uses the current working directory for its local data folder.
; Shortcuts therefore set {app} as the working directory.

#define MyAppName "Campus LMS"
#define MyAppVersion "1.0.0"
#define MyAppExeName "CampusLMS.exe"

[Setup]
AppId={{B8F7A9D1-5E3C-4D62-9A41-7C2E8F6B310D}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={localappdata}\Programs\CampusLMS
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=installer-output
OutputBaseFilename=CampusLMS_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Dirs]
; Ensure the upload location exists and preserve user data on uninstall.
Name: "{app}\data"; Flags: uninsneveruninstall
Name: "{app}\data\uploads"; Flags: uninsneveruninstall

[Files]
; SQLite is statically linked into this executable, so no sqlite3.dll is required.
Source: "build\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Ship the existing tested database on first installation only.
; Keep it on uninstall and do not overwrite it during a later reinstall/update.
Source: "data\school_lms.db"; DestDir: "{app}\data"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Campus LMS"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent unchecked
