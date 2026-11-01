//! Generate a controller identity and print the public trust anchor.
//!
//! The private key is written to a file with owner-only permissions.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use zt_crypto::credential::ControllerIdentity;
use zt_crypto::identity::Identity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("controller.key"));

    let identity = Identity::generate()?;
    let controller = ControllerIdentity::new(identity);
    let seed = controller.public_key();

    let mut file = fs::File::create(&output)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "{}", hex::encode(seed))?;

    println!("controller id: {}", hex::encode(controller.controller_id()));
    println!("public key:    {}", hex::encode(controller.public_key()));
    println!("wrote:         {}", output.display());
    Ok(())
}
