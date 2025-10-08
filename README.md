<!-- markdownlint-disable MD041 -->
[//]: # (auto_md_to_doc_comments segment start A)

# msg_enc_dec

[//]: # (auto_cargo_toml_to_md start)

**Use SSH private-public keys to encode and decode messages**  
***version: 0.0.27 date: 2025-10-08 author: [bestia.dev](https://bestia.dev) repository: [GitHub](https://github.com/bestia-dev/msg_enc_dec)***

 ![maintained](https://img.shields.io/badge/maintained-green)
 ![work-in-progress](https://img.shields.io/badge/work_in_progress-yellow)
 ![rustlang](https://img.shields.io/badge/rustlang-orange)

[//]: # (auto_cargo_toml_to_md end)

 ![License](https://img.shields.io/badge/license-MIT-blue.svg)
 ![Rust](https://github.com/bestia-dev/msg_enc_dec/workflows/rust_fmt_auto_build_test/badge.svg)
 ![msg_enc_dec](https://bestia.dev/webpage_hit_counter/get_svg_image/779107454.svg)

[//]: # (auto_lines_of_code start)
[![Lines in Rust code](https://img.shields.io/badge/Lines_in_Rust-531-green.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
[![Lines in Doc comments](https://img.shields.io/badge/Lines_in_Doc_comments-165-blue.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
[![Lines in Comments](https://img.shields.io/badge/Lines_in_comments-57-purple.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
[![Lines in examples](https://img.shields.io/badge/Lines_in_examples-0-yellow.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)
[![Lines in tests](https://img.shields.io/badge/Lines_in_tests-0-orange.svg)](https://github.com/bestia-dev-work-in-progress/msg_enc_dec/)

[//]: # (auto_lines_of_code end)

Hashtags: #maintained #work-in-progress #rustlang  
My projects on GitHub are more like a tutorial than a finished product: [bestia-dev tutorials](https://github.com/bestia-dev/tutorials_rust_wasm).  

## Both sides must use msg_enc_dec

Install msg_enc_dec from GitHub on both sides of the communication: party_1 and party_2. It is preferred to use Rust locally to build the program, so you know exactly the code used in it.

```bash
cd ~/rustprojects
git clone git@github.com:bestia-dev-work-in-progress/msg_enc_dec.git
code msg_enc_dec
cargo auto release
alias msg_enc_dec="./target/release/msg_enc_dec"
msg_enc_dec 
# or
msg_enc_dec --help
```

## Create your SSH key

Create the SSH key and protect it with a passcode.

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/msg_enc_dec_ssh_1 -C "ssh key for msg_enc_dec"
```

Save the file `msg_enc_dec_config.json` with the content:

```json
{
"msg_enc_dec_private_key_file_name":"msg_enc_dec_ssh_1"
}
```

The program `msg_enc_dec` will read this file to find the SSH private key in the `~/.ssh` folder.

## 1. Party_1: Send your SSH public key

To start the secure communication send your public key. This is not a secret.

## 2. Party_2: Encrypt a password

The party_2 will encrypt an ephemeral password with the received public key. The only one who can decrypt this is the owner of the private key, so party_1.
Send this encrypted message to party_1.

## 3. Party_1: decrypt the 





## Use SSH private key to encrypt decrypt messages

With one SSH private key, we can store many secret tokens.

```bash
msg_enc_dec list
msg_enc_dec store token_name
msg_enc_dec show token_name
msg_enc_dec delete token_name
```



## Development details

Read the development details in a separate md file:
[DEVELOPMENT.md](DEVELOPMENT.md)

## Releases changelog

Read the releases changelog in a separate md file:
[RELEASES.md](RELEASES.md)

## TODO

- better readme

## Open-source and free as a beer

My open-source projects are free as a beer (MIT license).  
I just love programming.  
But I need also to drink. If you find my projects and tutorials helpful, please buy me a beer by donating to my [PayPal](https://paypal.me/LucianoBestia).  
You know the price of a beer in your local bar ;-)  
So I can drink a free beer for your health :-)  
[Na zdravje!](https://translate.google.com/?hl=en&sl=sl&tl=en&text=Na%20zdravje&op=translate) [Alla salute!](https://dictionary.cambridge.org/dictionary/italian-english/alla-salute) [Prost!](https://dictionary.cambridge.org/dictionary/german-english/prost) [Nazdravlje!](https://matadornetwork.com/nights/how-to-say-cheers-in-50-languages/) 🍻

[//bestia.dev](https://bestia.dev)  
[//github.com/bestia-dev](https://github.com/bestia-dev)  
[//bestiadev.substack.com](https://bestiadev.substack.com)  
[//youtube.com/@bestia-dev-tutorials](https://youtube.com/@bestia-dev-tutorials)  

[//]: # (auto_md_to_doc_comments segment end A)
