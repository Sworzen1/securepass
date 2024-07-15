# Password Generator Library in Rust

This Rust library provides functions to generate random passwords, balance password, generate password with customizable options and password strength level based on calculation password entropy and check password has common words.

## Features

- Generate random passwords with specified length and charset.
- Option to include uppercase letters, numbers, and special characters.
- Password strength checking based on entropy level and common password dictionary.
- Balance weak password.
- Calculate password entropy.

## Usage

Add this library to your `Cargo.toml`:

```toml
[dependencies]
password_generator = "0.3.1"
```

To get default options:

```rs
let default_options = securepass::PasswordOptions::default();

```

Options struct and default:

```rs
PasswordOptions {
    pub length:usize, // 13
    pub include_special_chars:bool, // true
    pub include_uppercase:bool, // true
    pub include_numbers:bool, // true
    pub with_balancing:bool, // true
    pub phrase:Option<String> // None
}
```

To generate random password:

```rs
let new_random_password = securepass::generate_random_password(%EXAMPLE_CHARSET%, %LENGTH%); // returns String
```

To generate password with default options:

```rs
let default_options = securepass::PasswordOptions::default();
let password_with_options = default_options.generate_password(); // returns Result<String, String>
```

To generate password from phrase:

```rs
let options = securepass::PasswordOptions {
    phrase: Some("rust is awesome".to_string()),
    ..Default::default()
};
let password_from_phrase = options.generate_password(); // returns Result<String, String>
```

To check password strength:

```rs
let password_strength = securepass::check_password_strength(%PASSWORD%); // returns PasswordStrength enum
```

To balance password:

```rs
let mut password = %WEAK_PASSWORD%.to_string();
let balanced_password = securepass::balance_password(&mut password); // returns String
```

To calculate password entropy:

```rs
let entropy = securepass::calculate_entropy(%PASSWORD%); // returns float
```
