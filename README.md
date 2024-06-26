# Password Generator Library in Rust

This Rust library provides functions to generate random passwords, balance password, generate password with customizable options and check password strength level.

## Features

- Generate random passwords with specified length and character sets.
- Option to include uppercase letters, numbers, and special characters.
- Password strength checking based on character variety and length.
- Optional phrase-based password generation.
- Balance weak password.

## Usage

Add this library to your `Cargo.toml`:

```toml
[dependencies]
password_generator = "0.2.2"
```

To generate random password:

```rs
let new_random_password = securepass::generate_random_password(%EXAMPLE_CHARSET%, %LENGTH%);
```

To generate password without and with options:

```rs
let password_without_options = securepass::generate_password(None)

let options = securepass::PasswordOptions {
        length: Some(15),
        include_special_chars: Some(true),
        include_uppercase: Some(true),
        include_numbers: Some(true),
        with_balancing: Some(true),
        phrase: None,
    };

    let password_with_options = securepass::generate_password(Some(options));
```

To generate password from phrase:

```rs
let options = securepass::PasswordOptions {
        length: Some(12),
        include_special_chars: Some(false),
        include_uppercase: Some(false),
        include_numbers: Some(false),
        with_balancing: Some(false),
        phrase: Some("rust is awesome".to_string()),
    };
    let password_from_phrase = securepass::generate_password(Some(options_with_phrase));
```

To check password strength:

```rs
 let password_strength = securepass::check_password_strength(%PASSWORD%);
```

To balance password:

```rs
let mut password = %WEAK_PASSWORD%;
    let balance_options = securepass::PasswordOptions {
        length: None,
        include_special_chars: Some(true),
        include_uppercase: Some(true),
        include_numbers: Some(true),
        with_balancing: Some(true),
        phrase: None,
    };
    securepass::balance_password(&mut password, &balance_options);
```
