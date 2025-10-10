//! src/bin/msg_enc_dec/main.rs

// region: auto_md_to_doc_comments include README.md A //!

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

// region: general functions

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

  Use X25519 to securely share a secret token over any communication channel.
  Use ssh private key to encrypt and save locally the shared secret token.
  Use symmetric encryption to encode and decode messages and files
  for a secure communication between two users.

  This is the help for this program.
{GREEN}msg_enc_dec --help{RESET}
  
  register completion for msg_enc_dec
{GREEN}msg_enc_dec activate_completion{RESET}

  {YELLOW}INITIALIZATION{RESET}

  Do it only once. Create your ssh key if you don't have it already. 
  Give it a good passcode and remember it. 
  Nobody can help you if you forget it. 
  You would have to delete the old key and create a new one.
  This ssh key will be used to save locally the secret session token for the communication.
{GREEN}msg_enc_dec create_ssh_key {RESET}

  {YELLOW}HANDSHAKE{RESET}

  Create a new static key-pair X25519 and 
  send the public key to the other party. 
  It is not a secret.
{GREEN}msg_enc_dec send_public_key {RESET}

  Receive the other's public key and calculate the shared secret.
  Save the shared secret encrypted.
{GREEN}msg_enc_dec receive_public_key {RESET}

  {YELLOW}COMMUNICATION{RESET}

  Encrypt message and send the encrypted text.
{GREEN}msg_enc_dec message_encrypt {RESET}
  Decrypt the received message.
{GREEN}msg_enc_dec message_decrypt {RESET}
  Encrypt file and send the encrypted file.
{GREEN}msg_enc_dec file_encrypt {RESET}
  Decrypt the received file.
{GREEN}msg_enc_dec file_decrypt {RESET}

  {YELLOW}© 2025 bestia.dev  MIT License github.com/bestia-dev/msg_enc_dec{RESET}
"#
    );
    Ok(())
}


fn activate_completion() -> anyhow::Result<()>{
    println!("register completion for msg_enc_dec."):
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
    encrypt_and_save_file(static_secret.to_bytes(), "static_secret")?;

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

/// Save the secret bytes encrypted into local folder.
fn encrypt_and_save_file(secret_bytes: [u8; 32], extension: &str) -> Result<(), anyhow::Error> {
    let private_key_file_name = &MSG_ENC_DEC_CONFIG
        .get()
        .context("MSG_ENC_DEC_CONFIG is None")?
        .msg_enc_dec_private_key_file_name;
    let (plain_seed_bytes_32bytes, plain_seed_string) = ende::random_seed_32bytes_and_string()?;
    let private_key_path_struct = ende::PathStructInSshFolder::new(private_key_file_name.to_string())?;
    let secret_passcode_32bytes: SecretBox<[u8; 32]> =
        ende::sign_seed_with_ssh_agent_or_private_key_file(&private_key_path_struct, plain_seed_bytes_32bytes)?;
    let secret_string = secrecy::SecretString::from(ende::encode64_from_32bytes_to_string(secret_bytes)?);
    let plain_encrypted_text = ende::encrypt_symmetric(secret_passcode_32bytes, secret_string)?;
    let encrypted_secret_file_path = CrossPathBuf::new(&format!("{private_key_file_name}.{extension}"))?;
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
    let other_public_key = x25519_dalek::PublicKey::try_from(other_public_key)?;

    // load and decrypt the static secret
    let static_secret_bytes = load_and_decrypt("static_secret")?;
    let static_secret = x25519_dalek::StaticSecret::try_from(static_secret_bytes)?;

    // calculate shared secret
    let shared_secret = static_secret.diffie_hellman(&other_public_key);

    // save encrypted shared secret
    encrypt_and_save_file(shared_secret.to_bytes(), "shared_secret")?;

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

// load and decrypt secret
fn load_and_decrypt(extension: &str) -> Result<[u8; 32], anyhow::Error> {
    let private_key_file_name = &MSG_ENC_DEC_CONFIG
        .get()
        .context("MSG_ENC_DEC_CONFIG is None")?
        .msg_enc_dec_private_key_file_name;
    let encrypted_static_secret_file_path = CrossPathBuf::new(&format!("{private_key_file_name}.{extension}"))?;
    let encrypted_static_secret_file_string = encrypted_static_secret_file_path.read_to_string()?;
    let json_struct: EncryptedTextWithMetadata = serde_json::from_str(&encrypted_static_secret_file_string)?;
    let plain_seed_bytes_32bytes = ende::decode64_from_string_to_32bytes(&json_struct.plain_seed_string)?;
    let private_key_path_struct = ende::PathStructInSshFolder::new(private_key_file_name.to_string())?;
    let secret_passcode_32bytes: SecretBox<[u8; 32]> =
        ende::sign_seed_with_ssh_agent_or_private_key_file(&private_key_path_struct, plain_seed_bytes_32bytes)?;
    let secret_string = ende::decrypt_symmetric(secret_passcode_32bytes, json_struct.plain_encrypted_text)?;
    let secret_bytes = ende::decode64_from_string_to_32bytes(secret_string.expose_secret())?;
    Ok(secret_bytes)
}

/// encrypt message from terminal
fn message_encrypt() -> anyhow::Result<()> {
    let shared_secret_bytes = load_and_decrypt("shared_secret")?;
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

/// decrypt message from terminal
fn message_decrypt() -> anyhow::Result<()> {
    let shared_secret_bytes = load_and_decrypt("shared_secret")?;
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

/// encrypt file
fn file_encrypt(file_name: &str) -> anyhow::Result<()> {
    todo!();
    Ok(())
}

/// decrypt file
fn file_decrypt(file_name: &str) -> anyhow::Result<()> {
    todo!();
    Ok(())
}
