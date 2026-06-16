fn main() {
    let attrs = tauri_build::Attributes::new();
    #[cfg(target_os = "windows")]
    let attrs = attrs.windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(
            r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" name="com.vpn.client.windows11" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#,
        ),
    );
    tauri_build::try_build(attrs).expect("tauri build failed");
}
