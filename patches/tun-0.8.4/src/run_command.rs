/// Runs a command and returns an error if the command fails, just convenience for users.
#[doc(hidden)]
#[allow(dead_code)]
pub fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let full_cmd = format!("{} {}", command, args.join(" "));
    log::debug!("Running command: \"{full_cmd}\"...");
    let mut cmd = std::process::Command::new(command);
    cmd.args(args);
    // Without CREATE_NO_WINDOW a console child spawned from a GUI-subsystem
    // parent (leaf statically linked into fkey_app.exe, which has no console)
    // gets a brand-new console object, and Windows shows that console window.
    // Every other spawn in leaf goes through hidden_command(); this one did not.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let out = match cmd.output() {
        Ok(out) => out,
        Err(e) => {
            log::error!("Run command: \"{full_cmd}\" failed with: {e}");
            return Err(e);
        }
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        });
        let info = format!("Run command: \"{full_cmd}\" failed with {err}");
        log::error!("{info}");
        return Err(std::io::Error::other(info));
    }
    Ok(out.stdout)
}
