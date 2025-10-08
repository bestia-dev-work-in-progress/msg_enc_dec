//! src/bin/msg_enc_dec/main.rs

// region: auto_md_to_doc_comments include README.md A //!
//! # msg_enc_dec
//!
//! **Use SSH private-public keys to encode and decode messages**  
//! ***version: 0.0.75 date: 2025-10-06 author: [bestia.dev](https://bestia.dev) repository: [GitHub](https://github.com/bestia-dev/msg_enc_dec)***
//!
//!  ![maintained](https://img.shields.io/badge/maintained-green)
//!  ![work-in-progress](https://img.shields.io/badge/work_in_progress-green)
//!  ![rustlang](https://img.shields.io/badge/rustlang-orange)
//!
//!  ![License](https://img.shields.io/badge/license-MIT-blue.svg)
//!  ![Rust](https://github.com/bestia-dev/msg_enc_dec/workflows/rust_fmt_auto_build_test/badge.svg)
//!  ![msg_enc_dec](https://bestia.dev/webpage_hit_counter/get_svg_image/779107454.svg)
//!
//! [![Lines in Rust code](https://img.shields.io/badge/Lines_in_Rust-655-green.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//! [![Lines in Doc comments](https://img.shields.io/badge/Lines_in_Doc_comments-200-blue.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//! [![Lines in Comments](https://img.shields.io/badge/Lines_in_comments-75-purple.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//! [![Lines in examples](https://img.shields.io/badge/Lines_in_examples-0-yellow.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//! [![Lines in tests](https://img.shields.io/badge/Lines_in_tests-0-orange.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//!
//! Hashtags: #maintained #work-in-progress #rustlang  
//! My projects on GitHub are more like a tutorial than a finished product: [bestia-dev tutorials](https://github.com/bestia-dev/tutorials_rust_wasm).  
//!
//! ## create the SSH key
//!
//! Create the SSH key and protect it with a passcode.
//!
//! ```bash
//! ssh-keygen -t ed25519 -f msg_enc_dec_ssh_1 -C "vault for secret tokens"
//! ```
//!
//! Save the file `ssh_private_key_bare_file_name.cfg` with the content `msg_enc_dec_ssh_1`.  
//! The program `msg_enc_dec` will read this file to find the SSH private key in the `~/.ssh` folder.
//!
//! ## Use SSH private key to store passwords
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
//! ## convert to strong password
//!
//! I'd like to have a CLI where to input a humane easy to memorize password and convert it into a strong password.  
//!
//! ```bash
//! msg_enc_dec strong
//! ```
//!
//! Then sign it with a private key (this encryption is reversible using the public key).  
//! Then hash it (this is a one way encryption, so nobody can come back to the first secret).  
//! Finally, convert it into a string long 32 characters with ascii7 characters (lowercase, uppercase, numeric and special characters).  
//! What makes this conversion secure is: only the user of the private key can convert the easy password into the same strong_password.
//!
//! Strong passwords must use the clipboard. The risk is that it can stay in the clipboard and can be read from the clipboard.
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
use base64ct::Encoding;
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

use rsa::{pkcs8::DecodePublicKey, traits::PaddingScheme};
// import trait
use secrecy::ExposeSecret;

#[derive(serde::Deserialize, serde::Serialize)]
pub struct MsgEncDecConfig {
    pub msg_enc_dec_private_key_file_name: String,
}

/// Application state (static) is initialized only once in the main() function.
///
/// And then is accessible all over the code.
pub static MSG_ENC_DEC_CONFIG: std::sync::OnceLock<MsgEncDecConfig> = std::sync::OnceLock::new();

///main returns ExitCode
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

/// main() returns anyhow::Result
fn main_returns_anyhow_result() -> anyhow::Result<()> {
    tracing_init()?;
    msg_enc_dec_config_initialize()?;
    // super simple argument parsing. There are crates that can parse more complex arguments.
    match std::env::args().nth(1).as_deref() {
        None | Some("--help") | Some("-h") => print_help()?,
        Some("create_ssh_key") => create_ssh_key()?,
        Some("public_key") => public_key()?,
        Some("store_public_key_and_print_token") => store_public_key_and_print_token()?,
        Some("store_token") => store_token()?,
        Some("encrypt_message") => encrypt_message()?,
        Some("decrypt_message") => decrypt_message()?,

        Some("encrypt_file") => match std::env::args().nth(2).as_deref() {
            // second argument
            Some(file_name) => {
                encrypt_file(file_name);
            }
            None => eprintln!("{RED}Error: Missing arguments `file_name`.{RESET}"),
        },
        Some("decrypt_file") => match std::env::args().nth(2).as_deref() {
            // second argument
            Some(file_name) => {
                decrypt_file(file_name);
            }
            None => eprintln!("{RED}Error: Missing arguments `file_name`.{RESET}"),
        },

        _ => eprintln!("{RED}Error: Unrecognized arguments. Try `msg_enc_dec --help`{RESET}"),
    }
    Ok(())
}

// region: general functions

/// Initialize tracing to file logs/automation_tasks_rs.log
///
/// The folder logs/ is in .gitignore and will not be committed.
pub fn tracing_init() -> anyhow::Result<()> {
    // uncomment this line to enable tracing to file
    // let file_appender = tracing_appender::rolling::daily("logs", "msg_enc_dec_your_password.log");

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
    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("hyper_util=error".parse()?)
        .add_directive("reqwest=error".parse()?);

    tracing_subscriber::fmt()
        .with_file(true)
        .with_max_level(tracing::Level::DEBUG)
        .with_timer(timer)
        .with_line_number(true)
        .with_ansi(false)
        //.with_writer(file_appender)
        .with_env_filter(filter)
        .init();
    Ok(())
}

// endregion: general functions

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

/// Print help on the terminal.
fn print_help() -> anyhow::Result<()> {
    println!(
        r#"
  {YELLOW}Welcome to msg_enc_dec CLI{RESET}
  Use SSH private-public keys to encode and decode messages and files
  for a secure communication between two users.

  This is the help for this program.
{GREEN}msg_enc_dec --help{RESET}

  {YELLOW}INITIALIZATION{RESET}

  Do it only once. Create your ssh key if you don't have it already. 
  Give it a good passcode and remember it. 
  Nobody can help you if you forget it. 
  You would heave to delete the old key and create a new one.
{GREEN}msg_enc_dec create_ssh_key {RESET}

  {YELLOW}HANDSHAKE{RESET}

  Send the public key to the other party. 
  It is not a secret.
{GREEN}msg_enc_dec public_key {RESET}

  Store the received public key and print the encrypted token.
  Only the owner of the private key is able to decrypt it.
{GREEN}msg_enc_dec store_public_key_and_print_token {RESET}

  Store the encrypted token.
  Only the owner of the private key is able to decrypt it.
{GREEN}msg_enc_dec store_token {RESET}

  {YELLOW}COMMUNICATION{RESET}

  Encrypt message and send the encrypted text.
{GREEN}msg_enc_dec encrypt_message {RESET}
  Decrypt the received message.
{GREEN}msg_enc_dec decrypt_message {RESET}
  Encrypt file and send the encrypted file.
{GREEN}msg_enc_dec encrypt_file {RESET}
  Decrypt the received file.
{GREEN}msg_enc_dec decrypt_file {RESET}

  {YELLOW}© 2025 bestia.dev  MIT License github.com/bestia-dev/msg_enc_dec{RESET}
"#
    );
    Ok(())
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
    println!("  {YELLOW}Copy and run this command manually in the terminal. {RESET}");
    println!("  {YELLOW}Give it a good passcode and remember it. {RESET}");
    println!("  {YELLOW}Nobody can help you if you forget the passcode. {RESET}");
    println!("  {YELLOW}You would heave to delete the old key and create a new one. {RESET}");
    println!(r#"{GREEN}ssh-keygen -t rsa -b 4096 -f ~/.ssh/msg_enc_dec_ssh_1 -C "ssh key for msg_enc_dec" {RESET}"#);
    println!();
    println!("  {YELLOW}After that use 'msg_enc_dec public_key'. {RESET}");
    Ok(())
}

/// Print the public key.
fn public_key() -> anyhow::Result<()> {
    let private_key_file_name = &MSG_ENC_DEC_CONFIG
        .get()
        .context("MSG_ENC_DEC_CONFIG is None")?
        .msg_enc_dec_private_key_file_name;
    let public_key_path = CrossPathBuf::new(&format!("~/.ssh/{}.pub", private_key_file_name))?;
    let public_key = public_key_path.read_to_string()?;
    println!("  {YELLOW}Send this public key to the other party. This is not a secret. {RESET}");
    println!("  {YELLOW}They must use 'msg_enc_dec store_public_key_and_print_token'. {RESET}");
    println!("  {YELLOW}and then send you the token. {RESET}");
    println!("  {YELLOW}It is encrypted, only the owner of the private key can decrypt it. {RESET}");
    println!(r#"{GREEN}{public_key} {RESET}"#);

    Ok(())
}

/// store public key and print token
fn store_public_key_and_print_token() -> anyhow::Result<()> {
    let public_key = inquire::Text::new(&format!("{BLUE}Copy the public rsa key of the other party:{RESET}")).prompt()?;
    let other_party_public_key_path = CrossPathBuf::new("other_party_public_key")?;
    other_party_public_key_path.write_str_to_file(&public_key)?;
    // random new password
    // prepare the random bytes, sign it with the other public key, that is the true password used for communication

    let (plain_seed_bytes_32bytes, plain_seed_string) = ende::random_seed_32bytes_and_string()?;
    // TODO: encrypt before saving file using ssh-agent
    let security_token_dec = CrossPathBuf::new("security_token_dec_1.txt")?;
    security_token_dec.write_str_to_file(&plain_seed_string)?;

    // first try to use the private key from ssh-agent, else use the private file with user interaction
    let public_key = ssh_key::PublicKey::read_openssh_file(&other_party_public_key_path.to_path_buf_current_os())?;
    let rsa_public_key = public_key
        .key_data()
        .rsa()
        .ok_or_else(|| anyhow::anyhow!("not possible rsa public key"))?;
    let rsa_public_key: rsa::RsaPublicKey = rsa_public_key.try_into()?;

    let mut rng = rand::thread_rng();
    let enc_data = rsa_public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &plain_seed_bytes_32bytes)
        .expect("failed to encrypt");
    let token_string = base64ct::Base64Url::encode_string(&enc_data);
    let security_token_enc = CrossPathBuf::new("security_token_enc_1.txt")?;
    security_token_enc.write_str_to_file(&token_string)?;

    println!("  {YELLOW}Send this encrypted security token to the other party.{RESET}");
    println!("  {YELLOW}Only the owner of the private key can decrypt this.{RESET}");

    println!(r#"{GREEN}{token_string} {RESET}"#);

    Ok(())
}

/// store token
fn store_token() -> anyhow::Result<()> {
    let token = inquire::Text::new(&format!("{BLUE}Copy the encrypted security token.{RESET}")).prompt()?;
    let security_token_enc_path = CrossPathBuf::new("security_token_enc_2.txt")?;
    security_token_enc_path.write_str_to_file(&token)?;
    let token_bytes = base64ct::Base64Url::decode_vec(&token).unwrap();

    // decrypt security token
    let private_key_path = CrossPathBuf::new("~/.ssh/msg_enc_dec_ssh_1")?;
    let private_key = ssh_key::PrivateKey::read_openssh_file(&private_key_path.to_path_buf_current_os())?;
    let private_key = private_key.decrypt("a")?;
    let rsa_key_pair = private_key
        .key_data()
        .rsa()
        .ok_or_else(|| anyhow::anyhow!("not possible rsa private key"))?;
    let rsa_private_key = rsa::RsaPrivateKey::from_p_q(
        rsa_key_pair.private.p.clone().try_into()?,
        rsa_key_pair.private.q.clone().try_into()?,
        rsa_key_pair.public.e.clone().try_into()?,
    )?;

    let dec_data = rsa_private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &token_bytes)
        .expect("failed to decrypt");
    let token_string = base64ct::Base64Url::encode_string(&dec_data);

    // TODO: encrypt before saving file using ssh-agent
    let security_token_dec = CrossPathBuf::new("security_token_dec_2.txt")?;
    security_token_dec.write_str_to_file(&token_string)?;

    println!("  {YELLOW}Security token stored.{RESET}");
    println!("  {YELLOW}Now you can encrypt and decrypt messages and files.{RESET}");

    Ok(())
}

/// encrypt message from terminal
fn encrypt_message() -> anyhow::Result<()> {
    todo!();
    Ok(())
}

/// decrypt message from terminal
fn decrypt_message() -> anyhow::Result<()> {
    todo!();
    Ok(())
}

/// encrypt file
fn encrypt_file(file_name: &str) -> anyhow::Result<()> {
    todo!();
    Ok(())
}

/// decrypt file
fn decrypt_file(file_name: &str) -> anyhow::Result<()> {
    todo!();
    Ok(())
}
