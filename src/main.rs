//! src/bin/msg_enc_dec/main.rs

// region: auto_md_to_doc_comments include README.md A //!
//! # msg_enc_dec
//!
//! **Use SSH keys, Ed22519, X25519 and GCM to encode and decode messages and files for communication**  
//! ***version: 1.0.2 date: 2025-10-14 author: [bestia.dev](https://bestia.dev) repository: [GitHub](https://github.com/bestia-dev/msg_enc_dec)***
//!
//!  ![maintained](https://img.shields.io/badge/maintained-green)
//!  ![work-in-progress](https://img.shields.io/badge/work_in_progress-yellow)
//!  ![rustlang](https://img.shields.io/badge/rustlang-orange)
//!
//!  ![License](https://img.shields.io/badge/license-MIT-blue.svg)
//!  ![Rust](https://github.com/bestia-dev/msg_enc_dec/workflows/rust_fmt_auto_build_test/badge.svg)
//!  ![msg_enc_dec](https://bestia.dev/webpage_hit_counter/get_svg_image/124137175.svg)
//!
//! [![Lines in Rust code](https://img.shields.io/badge/Lines_in_Rust-607-green.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
//! [![Lines in Doc comments](https://img.shields.io/badge/Lines_in_Doc_comments-91-blue.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
//! [![Lines in Comments](https://img.shields.io/badge/Lines_in_comments-77-purple.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
//! [![Lines in examples](https://img.shields.io/badge/Lines_in_examples-0-yellow.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
//! [![Lines in tests](https://img.shields.io/badge/Lines_in_tests-0-orange.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
//!
//! Hashtags: #maintained #work-in-progress #rustlang  
//! My projects on GitHub are more like a tutorial than a finished product: [bestia-dev tutorials](https://github.com/bestia-dev/tutorials_rust_wasm).  
//!
//! ## ⚠️ Security Warning
//!
//! The implementation contained in this crate has never been independently audited!
//!
//! USE AT YOUR OWN RISK!
//!
//! ## Try it
//!
//! For encrypted communication between two parties, both must use msg_enc_dec.  
//! Install msg_enc_dec from GitHub.  
//! It is preferred to use Rust locally to build the program, so you know exactly the source code.
//!
//! ```bash
//! cd ~/rustprojects
//! git clone git@github.com:bestia-dev-work-in-progress/msg_enc_dec.git
//! code msg_enc_dec
//! cargo auto release
//! alias msg_enc_dec="./target/release/msg_enc_dec"
//! msg_enc_dec --help
//! ```
//!
//! ![alt text](images/image_01.png)
//!
//!
//! ## activate bash completion
//!
//!
//!
//! ## Create your SSH key
//!
//! Create the SSH key and protect it with a passcode.
//!
//! ```bash
//! ssh-keygen -t rsa -b 2048 -f ~/.ssh/msg_enc_dec_ssh_1 -C "ssh key for msg_enc_dec"
//! ```
//!
//! Save the file `msg_enc_dec_config.json` with the content:
//!
//! ```json
//! {
//! "msg_enc_dec_private_key_file_name":"msg_enc_dec_ssh_1"
//! }
//! ```
//!
//! The program `msg_enc_dec` will read this file to find the SSH private key in the `~/.ssh` folder.
//!
//! ## 1. Party_1: Send your SSH public key
//!
//! To start the secure communication send your public key. This is not a secret.
//!
//! ## 2. Party_2: Encrypt a password
//!
//! The party_2 will encrypt an ephemeral password with the received public key. The only one who can decrypt this is the owner of the private key, so party_1.
//! Send this encrypted message to party_1.
//!
//! ## 3. Party_1: decrypt the
//!
//!
//!
//!
//! ## Cryptography
//!
//! Cryptography is a technique of securing information and communications using codes to ensure confidentiality, integrity and authentication.  
//! Modern ciphers, such as the Advanced Encryption Standard (AES), are considered virtually unbreakable.  
//! Secret key cryptography, also known as symmetric encryption, uses a single key to encrypt and decrypt a message.  
//! Public key cryptography (PKC), or asymmetric cryptography, uses mathematical functions to create codes that are exceptionally difficult to crack. It enables people to communicate securely over a non-secure communications channel without the need for a secret key.  
//! <https://www.fortinet.com/resources/cyberglossary/what-is-cryptography>
//!
//! ## OpenSSH
//!
//! OpenSSH is the premier connectivity tool for remote login with the SSH protocol. It encrypts all traffic to eliminate eavesdropping, connection hijacking, and other attacks.  
//! Key management with ssh-add, ssh-keysign, ssh-keyscan, and ssh-keygen, ssh-agent.  
//! <https://www.openssh.com/>
//!
//! Open SSH uses Ed22519 for authentication. The SSH servers has a list of public keys that are authorized. The handshake: The server sends a random message. The client signs it with the private key Ed25519. The SSH server verifies the signature with the public key Ed25519.
//!
//! OpenSSH comes with tools to manage keys and it is a knowledge every developer learns early and thoroughly. The private key is protected by a passphrase. For repetitive use of the same private key I can use ssh-agent to input the passphrase only once. Usually the key inside ssh-agent is time limited for example for one hour.
//!
//! ## bestia.dev
//!
//! I use Ed25519 to store encrypted values on the local disk. First I create random 32 bytes called the 'seed'. I sign it with the private key Ed25519. That becomes the password I use to symmetrically encrypt GCM the secret value. In the saved file there is in plain text the seed and the encrypted data. Only the owner of the private key Ed25519 can sign the seed to get the password to then decrypt GCM the data.
//!
//! ## Ed25519
//!
//! Ed25519 is the EdDSA signature scheme using SHA-512 (SHA-2) and an elliptic curve related to Curve25519.  
//! In public-key cryptography, Edwards-curve Digital Signature Algorithm (EdDSA) is a digital signature scheme using a variant of Schnorr signature based on twisted Edwards curves. It is designed to be faster than existing digital signature schemes without sacrificing security.  
//! Public keys are 256 bits long and signatures are 512 bits long.  
//! <https://en.wikipedia.org/wiki/EdDSA#Ed25519>
//!
//! Ed25519 is a signature scheme. It does not do encryption.  
//!
//! ## X25519
//!
//! X25519 is the name given to the Elliptic Curve Diffie-Hellman (ECDH) key exchange built on Ed22519.  
//! <https://medium.com/@aditrizky052/unlocking-the-power-of-curve25519-ed25519-x25519-the-modern-pillars-of-secure-and-high-speed-a3daefbad0a4>
//!
//! The Diffie-Hellman algorithm (DH) is used for secret key exchanges and requires two people to agree on a large prime number.  
//! Key Exchange Algorithm KEA is a variation of the Diffie-Hellman algorithm and was proposed as a method for key exchange.  
//! <https://www.fortinet.com/resources/cyberglossary/what-is-cryptography>
//!
//! ## GCM
//!
//! In cryptography, Galois/Counter Mode (GCM) is a mode of operation for symmetric-key cryptographic block ciphers which is widely adopted for its performance. The GCM algorithm provides data authenticity, integrity and confidentiality and belongs to the class of authenticated encryption with associated data (AEAD) methods.  
//! <https://en.wikipedia.org/wiki/Galois/Counter_Mode>  
//!
//! ## Base64
//!
//! In computer programming, Base64 is a group of binary-to-text encoding schemes that transforms binary data into a sequence of printable characters, limited to a set of 64 unique characters. More specifically, the source binary data is taken 6 bits at a time, then this group of 6 bits is mapped to one of 64 unique characters.  
//! The particular set of 64 characters chosen to represent the 64-digit values for the base varies between implementations. The general strategy is to choose 64 characters that are common to most encodings and that are also printable. For example, MIME's Base64 implementation uses A–Z, a–z, and 0–9 for the first 62 values. Other variations share this property but differ in the symbols chosen for the last two values.  
//! The base64url RFC 4648 §5 standard is URL and filename-safe, where the '+' and '/' characters are replaced by '-' and '_'.  
//! The = symbol is also used as a padding suffix. The padding character is not essential for decoding, since the number of missing bytes can be inferred from the length of the encoded text. In some implementations, the padding character is mandatory, while for others it is not used.
//! <https://en.wikipedia.org/wiki/Base64>
//!
//!
//!
//!
//!
//!
//!
//! ## Use SSH keys, Ed22519, X25519 and GCM to encode and decode messages and files for communication
//!
//! With one SSH private key, we can store many secret tokens.
//!
//! ```bash
//! msg_enc_dec list
//! msg_enc_dec store token_name
//! msg_enc_dec show token_name
//! msg_enc_dec delete token_name
//! ```
//!
//!
//!
//! ## Development details
//!
//! Read the development details in a separate md file:
//! [DEVELOPMENT.md](DEVELOPMENT.md)
//!
//! ## Releases changelog
//!
//! Read the releases changelog in a separate md file:
//! [RELEASES.md](RELEASES.md)
//!
//! ## TODO
//!
//! - better readme
//!
//! ## Open-source and free as a beer
//!
//! My open-source projects are free as a beer (MIT license).  
//! I just love programming.  
//! But I need also to drink. If you find my projects and tutorials helpful, please buy me a beer by donating to my [PayPal](https://paypal.me/LucianoBestia).  
//! You know the price of a beer in your local bar ;-)  
//! So I can drink a free beer for your health :-)  
//! [Na zdravje!](https://translate.google.com/?hl=en&sl=sl&tl=en&text=Na%20zdravje&op=translate) [Alla salute!](https://dictionary.cambridge.org/dictionary/italian-english/alla-salute) [Prost!](https://dictionary.cambridge.org/dictionary/german-english/prost) [Nazdravlje!](https://matadornetwork.com/nights/how-to-say-cheers-in-50-languages/) 🍻
//!
//! [//bestia.dev](https://bestia.dev)  
//! [//github.com/bestia-dev](https://github.com/bestia-dev)  
//! [//bestiadev.substack.com](https://bestiadev.substack.com)  
//! [//youtube.com/@bestia-dev-tutorials](https://youtube.com/@bestia-dev-tutorials)  
//!
// endregion: auto_md_to_doc_comments include README.md A //!

mod encrypt_decrypt_with_ssh_key_mod;

use anyhow::Context;
use encrypt_decrypt_with_ssh_key_mod::encrypt_decrypt_mod as ende;

// region: Public API constants
// ANSI colors for Linux terminal
// https://github.com/shiena/ansicolor/blob/master/README.md
/// ANSI color
pub const RED: &str = "\x1b[31m";
/// ANSI color
#[allow(dead_code)]
pub const GREEN: &str = "\x1b[32m";
/// ANSI color
pub const YELLOW: &str = "\x1b[33m";
/// ANSI color
#[allow(dead_code)]
pub const BLUE: &str = "\x1b[34m";
/// ANSI color
pub const RESET: &str = "\x1b[0m";
// endregion: Public API constants

use crossplatform_path::CrossPathBuf;

// import trait
use secrecy::{ExposeSecret, SecretBox, SecretString};
#[allow(unused_imports)]
use tracing::{debug, error, info};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct MsgEncDecConfig {
    pub msg_enc_dec_private_key_file_name: String,
}

/// Application state (static) is initialized only once in the main() function.
///
/// And then is accessible all over the code.
pub static MSG_ENC_DEC_CONFIG: std::sync::OnceLock<MsgEncDecConfig> = std::sync::OnceLock::new();

/// Struct that represents the json data saved in the '*.enc' file.
#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct EncryptedTextWithMetadata {
    pub(crate) plain_seed_string: String,
    pub(crate) plain_encrypted_text: String,
}

/// Function main() returns ExitCode.
fn main() -> std::process::ExitCode {
    match main_returns_anyhow_result() {
        Err(err) => {
            eprintln!("{}", err);
            // eprintln!("Exit program with failure exit code 1");
            std::process::ExitCode::FAILURE
        }
        Ok(()) => std::process::ExitCode::SUCCESS,
    }
}

/// Function main() returns anyhow::Result.
fn main_returns_anyhow_result() -> anyhow::Result<()> {
    tracing_init()?;
    msg_enc_dec_config_initialize()?;
    // super simple argument parsing. There are crates that can parse more complex arguments.
    match std::env::args().nth(1).as_deref() {
        None | Some("--help") | Some("-h") => print_help()?,
        // Register completion for msg_enc_dec  with the shell command 'complete -C'.
        Some("activate_completion") => activate_completion()?,
        // When registered completion calls msg_enc_dec, the first argument is the path of the program.
        Some("msg_enc_dec") => msg_enc_dec_completion()?,
        Some("create_ssh_key") => create_ssh_key()?,
        Some("send_public_key") => send_public_key()?,
        Some("receive_public_key") => receive_public_key()?,
        Some("message_encrypt") => message_encrypt()?,
        Some("message_decrypt") => message_decrypt()?,

        Some("file_encrypt") => match std::env::args().nth(2).as_deref() {
            // second argument
            Some(file_name) => {
                file_encrypt(file_name)?;
            }
            None => eprintln!("{RED}Error: Missing arguments `file_name`.{RESET}"),
        },
        Some("file_decrypt") => match std::env::args().nth(2).as_deref() {
            // second argument
            Some(file_name) => {
                file_decrypt(file_name)?;
            }
            None => eprintln!("{RED}Error: Missing arguments `file_name`.{RESET}"),
        },

        _ => eprintln!("{RED}Error: Unrecognized arguments. Try `msg_enc_dec --help`{RESET}"),
    }
    Ok(())
}

/// Initialize tracing to file logs/automation_tasks_rs.log
///
/// The folder logs/ is in .gitignore and will not be committed.
pub fn tracing_init() -> anyhow::Result<()> {
    // uncomment this line to enable tracing to file
    // and the line in tracing_subscriber with_writer(file_appender)
    let file_appender = tracing_appender::rolling::daily("logs", "msg_enc_dec.log");

    let offset = time::UtcOffset::current_local_offset()?;
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(
        offset,
        time::macros::format_description!("[hour]:[minute]:[second].[subsecond digits:6]"),
    );

    // Filter out logs from: hyper_util, reqwest
    // A filter consists of one or more comma-separated directives
    // target[span{field=value}]=level
    // examples: tokio::net=info
    // directives can be added with the RUST_LOG environment variable:
    // export RUST_LOG=automation_tasks_rs=trace
    // Unset the environment variable RUST_LOG
    // unset RUST_LOG
    let filter = tracing_subscriber::EnvFilter::default()
        .add_directive(tracing::level_filters::LevelFilter::DEBUG.into())
        .add_directive("hyper_util=error".parse()?)
        .add_directive("reqwest=error".parse()?);

    tracing_subscriber::fmt()
        .with_file(true)
        .with_timer(timer)
        .with_line_number(true)
        .with_ansi(false)
        .with_writer(file_appender)
        .with_env_filter(filter)
        .init();
    Ok(())
}

/// Application state (static) is initialized only once in the main() function.
///
/// And then is accessible all over the code.
fn msg_enc_dec_config_initialize() -> anyhow::Result<()> {
    if MSG_ENC_DEC_CONFIG.get().is_some() {
        return Ok(());
    }

    let msg_enc_dec_config_json = std::fs::read_to_string("msg_enc_dec_config.json")?;
    let msg_enc_dec_config: MsgEncDecConfig = serde_json::from_str(&msg_enc_dec_config_json)?;
    let _ = MSG_ENC_DEC_CONFIG.set(msg_enc_dec_config);
    Ok(())
}

/// Print help to the terminal.
fn print_help() -> anyhow::Result<()> {
    println!(
        r#"
  {YELLOW}Welcome to msg_enc_dec CLI {RESET}

  Use SSH keys, Ed22519, X25519 and GCM to encode and decode messages and files for communication.
  Use ssh private key Ed22519 to encrypt and save locally the shared secret token.
  Use symmetric encryption GCM to encode and decode messages and files
  for secure communication between two users.

  This is the help for this program.
{GREEN}msg_enc_dec --help {RESET}
  
  Activate bash completion for msg_enc_dec.
{GREEN}msg_enc_dec activate_completion {RESET}

  {YELLOW}INITIALIZATION {RESET}

  Do it only once. Create your ssh key if you don't have it already. 
  Give it a good passphrase and remember it. 
  Nobody can help you if you forget it. 
  You would have to delete the old key and create a new one.
  This ssh key will be used to save locally the secret session token for the communication.
{GREEN}msg_enc_dec create_ssh_key {RESET}

  {YELLOW}HANDSHAKE {RESET}

  You can use ssh-agent to type the passphrase of the ssh private key only once for one hour.
{GREEN}ssh-add -t 1h msg_enc_dec_ssh_1 {RESET}

  Create a new static key-pair X25519 and send the public key to the other party. 
  It is not a secret. You can use any communication available: email, whatsapp, messenger, sms,...
  Both users must send their public key to the other user.
{GREEN}msg_enc_dec send_public_key {RESET}

  Receive the other's public key and calculate the shared secret.
  Save the encrypted shared secret for later use.
{GREEN}msg_enc_dec receive_public_key {RESET}

  {YELLOW}COMMUNICATION {RESET}

  Encrypt message and send the encrypted text.
{GREEN}msg_enc_dec message_encrypt {RESET}
  Decrypt the received message.
{GREEN}msg_enc_dec message_decrypt {RESET}
  Encrypt file and send the encrypted file.
{GREEN}msg_enc_dec file_encrypt file_name {RESET}
  Decrypt the received file.
{GREEN}msg_enc_dec file_decrypt file_name{RESET}

  {YELLOW}© 2025 bestia.dev  MIT License github.com/bestia-dev/msg_enc_dec {RESET}
"#
    );
    Ok(())
}

/// Activate completion with the bash command complete.
fn activate_completion() -> anyhow::Result<()> {
    println!("Register completion for msg_enc_dec.");
    println!("complete -C msg_enc_dec msg_enc_dec");
    let shell_command = r#"complete -C msg_enc_dec msg_enc_dec "#;
    let _status = std::process::Command::new("sh").arg("-c").arg(shell_command).spawn()?.wait()?;
    Ok(())
}

/// Sub-command for bash auto-completion of `msg_enc_dec`.
fn msg_enc_dec_completion() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let word_being_completed = args[2].as_str();

    let sub_commands = vec![
        "activate_completion",
        "create_ssh_key",
        "send_public_key",
        "receive_public_key",
        "message_encrypt",
        "message_decrypt",
        "file_encrypt",
        "file_decrypt",
    ];
    completion_return_one_or_more_sub_commands(sub_commands, word_being_completed);
    Ok(())
}

/// Print one or more sub_commands.
pub fn completion_return_one_or_more_sub_commands(sub_commands: Vec<&str>, word_being_completed: &str) {
    let mut sub_found = false;
    for sub_command in sub_commands.iter() {
        if sub_command.starts_with(word_being_completed) {
            println!("{sub_command}");
            sub_found = true;
        }
    }
    if !sub_found {
        // print all sub-commands
        for sub_command in sub_commands.iter() {
            println!("{sub_command}");
        }
    }
}

/// Create ssh key and config json.
fn create_ssh_key() -> anyhow::Result<()> {
    let config_path = CrossPathBuf::new("msg_enc_dec_config.json")?;
    config_path.write_str_to_file(
        r#"
{
"msg_enc_dec_private_key_file_name":"msg_enc_dec_ssh_1"
}   
"#,
    )?;

    println!("  {YELLOW}Generate the ssh private/public key pair. {RESET}");
    println!("  {YELLOW}Give it a good passphrase and remember it. {RESET}");
    println!("  {YELLOW}Nobody can help you if you forget the passphrase. {RESET}");
    println!("  {YELLOW}You would have to delete the old key and create a new one. {RESET}");
    println!("  {YELLOW}This ssh key will be used to save locally the secret session token for the communication. {RESET}");
    println!();
    println!(r#"  {YELLOW}ssh-keygen -t rsa -b 2048 -f ~/.ssh/msg_enc_dec_ssh_1 -C "ssh key for msg_enc_dec" {RESET}"#);

    let shell_command = r#"ssh-keygen -t ed25519 -f ~/.ssh/msg_enc_dec_ssh_1 -C "ssh key for msg_enc_dec" "#;
    let _status = std::process::Command::new("sh").arg("-c").arg(shell_command).spawn()?.wait()?;

    println!();
    println!("  {YELLOW}After ssh-keygen run 'msg_enc_dec send_public_key'. {RESET}");
    Ok(())
}

/// Print the static public key to be sent.
fn send_public_key() -> anyhow::Result<()> {
    // https://docs.rs/crate/x25519-dalek/
    // create static secret, because ephemeral secrets cannot be extracted and eaved to file.
    let static_secret: x25519_dalek::StaticSecret = x25519_dalek::StaticSecret::random();

    // Save the static secret encrypted into local folder.
    let private_key_file_name = get_private_key_file_name()?;
    let encrypted_secret_file_path = CrossPathBuf::new("static_secret.enc")?;
    encrypt_and_save_file(&private_key_file_name, static_secret.to_bytes(), &encrypted_secret_file_path)?;

    // Send the public key to the other party.
    let public_key = x25519_dalek::PublicKey::from(&static_secret);
    let public_key_string = ende::encode64_from_bytes_to_string(public_key.to_bytes().to_vec());

    println!("  {YELLOW}Send this public key to the other party. This is not a secret. {RESET}");
    println!("  {YELLOW}They must use 'msg_enc_dec receive_public_key'. {RESET}");
    println!("  {YELLOW}and then send you the encrypted session token. {RESET}");
    println!("  {YELLOW}It is encrypted, only the owner of the private key can decrypt it. {RESET}");
    println!(r#"{GREEN}{public_key_string} {RESET}"#);

    Ok(())
}

/// Save the secret bytes symmetrically encrypted into a file.
///
/// Use the private key to sign the random seed. The random seed is saved as plain inside the file.
/// The file is bas64 only to masquerade it a little bit.
fn encrypt_and_save_file(
    private_key_file_name: &str,
    secret_bytes: [u8; 32],
    encrypted_secret_file_path: &CrossPathBuf,
) -> Result<(), anyhow::Error> {
    let (plain_seed_bytes_32bytes, plain_seed_string) = ende::random_seed_32bytes_and_string()?;
    let private_key_path = CrossPathBuf::new(&format!("~/.ssh/{private_key_file_name}"))?;
    let secret_passcode_32bytes: SecretBox<[u8; 32]> =
        ende::sign_seed_with_ssh_agent_or_private_key_file(&private_key_path, plain_seed_bytes_32bytes)?;
    let secret_string = secrecy::SecretString::from(ende::encode64_from_32bytes_to_string(secret_bytes)?);
    let plain_encrypted_text = ende::encrypt_symmetric(secret_passcode_32bytes, secret_string)?;
    let json_struct = EncryptedTextWithMetadata {
        plain_seed_string,
        plain_encrypted_text,
    };
    let json_string = serde_json::to_string_pretty(&json_struct)?;
    encrypted_secret_file_path.write_str_to_file(&json_string)?;
    Ok(())
}

/// Receive public key, calculate shared secret, encrypt and store for later use.
fn receive_public_key() -> anyhow::Result<()> {
    let other_public_key = inquire::Text::new(&format!("{BLUE}Copy the public key received from the other party:{RESET}")).prompt()?;
    let other_public_key = ende::decode64_from_string_to_32bytes(&other_public_key)?;
    let other_public_key = x25519_dalek::PublicKey::from(other_public_key);

    // load and decrypt the static secret
    let private_key_file_name = get_private_key_file_name()?;
    let enc_file_path = CrossPathBuf::new("static_secret.enc")?;
    let static_secret_bytes = load_and_decrypt(&private_key_file_name, &enc_file_path)?;
    let static_secret = x25519_dalek::StaticSecret::from(static_secret_bytes);

    // calculate shared secret
    let shared_secret = static_secret.diffie_hellman(&other_public_key);

    // save encrypted shared secret
    let private_key_file_name = get_private_key_file_name()?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc")?;
    encrypt_and_save_file(&private_key_file_name, shared_secret.to_bytes(), &encrypted_secret_file_path)?;

    // for debugging I can write the encrypted session token that is created
    // let session_token_enc_path = CrossPathBuf::new("enc_session_token_1.txt")?;
    // session_token_enc_path.write_str_to_file(&plain_session_token)?;

    println!("  {YELLOW}The shared secret session token is saved.{RESET}");
    println!("  {YELLOW}Now you can encrypt and decrypt messages and files.{RESET}");
    println!(r#"{GREEN}msg_enc_dec message_encrypt {RESET}"#);
    println!(r#"{GREEN}msg_enc_dec message_decrypt {RESET}"#);
    println!(r#"{GREEN}msg_enc_dec file_encrypt file_name {RESET}"#);
    println!(r#"{GREEN}msg_enc_dec file_decrypt file_name {RESET}"#);

    Ok(())
}

// Load and decrypt secret.
fn load_and_decrypt(private_key_file_name: &str, encrypted_secret_file_path: &CrossPathBuf) -> Result<[u8; 32], anyhow::Error> {
    let encrypted_secret_file_string = encrypted_secret_file_path.read_to_string()?;
    let json_struct: EncryptedTextWithMetadata = serde_json::from_str(&encrypted_secret_file_string)?;
    let plain_seed_bytes_32bytes = ende::decode64_from_string_to_32bytes(&json_struct.plain_seed_string)?;
    let private_key_path = CrossPathBuf::new(&format!("~/.ssh/{private_key_file_name}"))?;
    let secret_passcode_32bytes: SecretBox<[u8; 32]> =
        ende::sign_seed_with_ssh_agent_or_private_key_file(&private_key_path, plain_seed_bytes_32bytes)?;
    let secret_string = ende::decrypt_symmetric(secret_passcode_32bytes, json_struct.plain_encrypted_text)?;
    let secret_bytes = ende::decode64_from_string_to_32bytes(secret_string.expose_secret())?;
    Ok(secret_bytes)
}

/// Get private key file name from global variable.
fn get_private_key_file_name() -> Result<String, anyhow::Error> {
    let private_key_file_name = &MSG_ENC_DEC_CONFIG
        .get()
        .context("MSG_ENC_DEC_CONFIG is None")?
        .msg_enc_dec_private_key_file_name;
    Ok(private_key_file_name.to_string())
}

/// Encrypt message from terminal.
fn message_encrypt() -> anyhow::Result<()> {
    let private_key_file_name = get_private_key_file_name()?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc")?;
    let shared_secret_bytes = load_and_decrypt(&private_key_file_name, &encrypted_secret_file_path)?;
    // just for debug
    // let shared_secret_string = ende::encode64_from_32bytes_to_string(shared_secret_bytes)?;
    //println!("{shared_secret_string}");
    let shared_secret = SecretBox::new(Box::new(shared_secret_bytes));

    let secret_message = inquire::Text::new(&format!("{BLUE}Write secret message to encrypt.{RESET}")).prompt()?;
    let secret_message = SecretString::from(secret_message);
    // encrypt secret message with symmetric encryption
    let encrypted_message = ende::encrypt_symmetric(shared_secret, secret_message)?;
    println!("Encrypted message:");
    println!("{encrypted_message}");
    Ok(())
}

/// Decrypt message from terminal.
fn message_decrypt() -> anyhow::Result<()> {
    let private_key_file_name = get_private_key_file_name()?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc")?;
    let shared_secret_bytes = load_and_decrypt(&private_key_file_name, &encrypted_secret_file_path)?;
    // just for debug
    // let shared_secret_string = ende::encode64_from_32bytes_to_string(shared_secret_bytes)?;
    //println!("{shared_secret_string}");
    let shared_secret = SecretBox::new(Box::new(shared_secret_bytes));

    let encrypted_message = inquire::Text::new(&format!("{BLUE}Write encrypted message to decrypt.{RESET}")).prompt()?;
    // decrypt secret message with symmetric encryption
    let encrypted_message = ende::decrypt_symmetric(shared_secret, encrypted_message)?;
    println!("Decrypted message:");
    println!("{}", encrypted_message.expose_secret());
    Ok(())
}

/// Encrypt file.
fn file_encrypt(file_name: &str) -> anyhow::Result<()> {
    let private_key_file_name = get_private_key_file_name()?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc")?;
    let shared_secret_bytes = load_and_decrypt(&private_key_file_name, &encrypted_secret_file_path)?;
    // just for debug
    // let shared_secret_string = ende::encode64_from_32bytes_to_string(shared_secret_bytes)?;
    //println!("{shared_secret_string}");
    let shared_secret = SecretBox::new(Box::new(shared_secret_bytes));
    println!("Read file: {file_name}");
    let vec_u8 = std::fs::read(file_name)?;
    let encrypted = ende::encrypt_symmetric_from_bytes(shared_secret, vec_u8)?;
    println!("Save encrypted file: {file_name}.enc");
    std::fs::write(format!("{file_name}.enc"), encrypted)?;
    Ok(())
}

/// Decrypt file.
fn file_decrypt(file_name: &str) -> anyhow::Result<()> {
    let private_key_file_name = get_private_key_file_name()?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc")?;
    let shared_secret_bytes = load_and_decrypt(&private_key_file_name, &encrypted_secret_file_path)?;
    // just for debug
    // let shared_secret_string = ende::encode64_from_32bytes_to_string(shared_secret_bytes)?;
    //println!("{shared_secret_string}");
    let shared_secret = SecretBox::new(Box::new(shared_secret_bytes));
    println!("Read encrypted file: {file_name}.enc");
    let encrypted_file = std::fs::read_to_string(format!("{file_name}.enc"))?;
    // decrypt secret message with symmetric encryption
    let decrypted_file = ende::decrypt_symmetric_to_bytes(shared_secret, encrypted_file)?;
    println!("Save decrypted file: {file_name}");
    std::fs::write(file_name, decrypted_file)?;
    Ok(())
}
