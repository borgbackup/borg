#define MyAppName "Borg for Windows"
#define MyAppVersion "1.1"
#define MyAppPublisher "The Borg Collective"
#define MyAppURL "https://borgbackup.rtfd.org/"
#define MyAppExeName "borg-shell.bat"

[Setup]
AppId={{1B6E8CD4-25F2-4400-A53F-4338D6614475}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={pf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
OutputBaseFilename=Borg Backup {#MyAppVersion} Setup
Compression=lzma/normal
SolidCompression=yes
SourceDir=..\..
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "deployment\windows\borg-shell.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "win32exe\bin\*"; DestDir: "{app}\bin"; Flags: replacesameversion recursesubdirs
Source: "win32exe\lib\*"; DestDir: "{app}\lib"; Flags: replacesameversion recursesubdirs
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: shellexec postinstall skipifsilent

