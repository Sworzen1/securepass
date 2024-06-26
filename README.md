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
password_generator = "0.2.4"
```

To get default options:

```rs
let default_options = securepass::PasswordOptions::default();

```

Options struct and default:

```rs
PasswordOptions {
    pub length:u32, // 12
    pub include_special_chars:bool, // true
    pub include_uppercase:bool, // true
    pub include_numbers:bool, // true
    pub with_balancing:bool, // true
    pub phrase:Option<String> // None
}
```

To generate random password:

```rs
let new_random_password = securepass::generate_random_password(%EXAMPLE_CHARSET%, %LENGTH%);
```

To generate password with default options:

```rs
let default_options = securepass::PasswordOptions::default();
let password_with_options = default_options.generate_password();
```

To generate password from phrase:

```rs
let options = securepass::PasswordOptions {
    phrase: Some("rust is awesome".to_string()),
    ..Default::default()
};
let password_from_phrase = options.generate_password();
```

To check password strength:

```rs
let password_strength = securepass::check_password_strength(%PASSWORD%);
```

To balance password:

```rs
let mut password = %WEAK_PASSWORD%.to_string();
let balance_options = securepass::PasswordOptions::default();
let balanced_password = balance_options.balance_password(&mut password);
```
