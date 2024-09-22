//! This crate provides functionality to generate and balance passwords
//! with various options and strengths.

use rand::{thread_rng, Rng};
use std::fs;
use std::path::Path;

/// Structure representing the specification of a password.
pub struct PasswordSpecification {
    /// Whether the password contains lowercase characters.
    pub has_lowercase: bool,
    /// Whether the password contains uppercase characters.
    pub has_uppercase: bool,
    /// Whether the password contains special characters.
    pub has_special: bool,
    /// Whether the password contains numerical characters.
    pub has_number: bool,
}

/// Enum representing the strength of a password.
pub enum PasswordStrength {
    /// Weak password strength.
    Weak,
    /// Medium password strength.
    Medium,
    /// Strong password strength.
    Strong,
}

/// Structure representing the options for password generation.
pub struct PasswordOptions {
    /// Length of the password.
    pub length: usize,
    /// Whether to include special characters in the password.
    pub include_special_chars: bool,
    /// Whether to include uppercase characters in the password.
    pub include_uppercase: bool,
    /// Whether to include numerical characters in the password.
    pub include_numbers: bool,
    /// Whether to balance the password to ensure it meets strength criteria.
    pub with_balancing: bool,
    /// Optional phrase to be included in the password.
    pub phrase: Option<String>,
}

const UPPERCASE_CHARSET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARSET: &str = "abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &str = "0123456789";
const SPECIAL_CHARSET: &str = "!@#$%^&*?(){}[]<>-_=+";

impl Default for PasswordOptions {
    /// Returns the default password options.
    fn default() -> Self {
        Self {
            length: 13,
            include_special_chars: true,
            include_uppercase: true,
            include_numbers: true,
            with_balancing: true,
            phrase: None,
        }
    }
}

impl PasswordOptions {
    /// Generates a password based on the specified options.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` with the generated password if successful, 
    /// or an `Err` with a message if the password length is less than 10.
    pub fn generate_password(&self) -> Result<String, String> {
        let length = self.length;
        if length < 10 {
            return Err(String::from("Password length less than 10 is considered weak."));
        }
        let charset = self.generate_charset();

        let mut password: String = generate_random_password(&charset, length);

        if self.phrase.is_none() && self.with_balancing {
            password = balance_password(&mut password);
        }

        Ok(password)
    }

    /// Generates the character set for password generation based on the options.
    ///
    /// # Returns
    ///
    /// A charset as a string from defined options 
    fn generate_charset(&self) -> String {
        let mut charset = String::from("");

        if let Some(existed_phrase) = &self.phrase {
            charset.push_str(&remove_whitespace(existed_phrase));
        } else {
            charset.push_str(LOWERCASE_CHARSET);
            if self.include_uppercase {
                charset.push_str(UPPERCASE_CHARSET);
            }
            if self.include_numbers {
                charset.push_str(NUMBERS);
            }
            if self.include_special_chars {
                charset.push_str(SPECIAL_CHARSET);
            }
        }

        charset
    }
}

/// Generates a random password from the given character set and length.
///
/// # Arguments
///
/// * `charset` - A string slice representing the set of characters to use.
/// * `length` - The length of the password.
///
/// # Returns
///
/// A string containing the generated password.
pub fn generate_random_password(charset: &str, length: usize) -> String {
    let mut rng_thread = thread_rng();
    (0..length)
        .map(|_| {
            let index = rng_thread.gen_range(0..charset.len());
            charset.chars().nth(index).unwrap()
        })
        .collect()
}

/// Balances a password to ensure it meets the specified criteria.
///
/// # Arguments
///
/// * `password` - A mutable string reference to the password to balance.
///
/// # Returns
///
/// A balanced password as a string.
pub fn balance_password(password: &mut String) -> String {
    let mut rng_thread = thread_rng();
    let optimal_password_length = PasswordOptions::default().length;

    if password.len() < optimal_password_length {
        let charset = PasswordOptions::default().generate_charset();
        let number_chars_to_add = optimal_password_length - password.len();
        if number_chars_to_add > 0 {
            let str_to_add = generate_random_password(&charset, number_chars_to_add);
            password.push_str(&str_to_add);
        }
    }
    loop {
        let password_str = check_password_strength(password).unwrap();
        let password_specification = check_password_specification(password);

        if let PasswordStrength::Strong = password_str {
            if password_specification.has_lowercase
                && password_specification.has_number
                && password_specification.has_special
                && password_specification.has_uppercase
            {
                break;
            }
        }

        replace_char(password, LOWERCASE_CHARSET, &mut rng_thread);
        replace_char(password, UPPERCASE_CHARSET, &mut rng_thread);
        replace_char(password, NUMBERS, &mut rng_thread);
        replace_char(password, SPECIAL_CHARSET, &mut rng_thread);
    }

    password.to_string()
}

/// Checks the strength of a password.
///
/// # Arguments
///
/// * `password` - A string slice representing the password.
///
/// # Returns
///
/// The password strength as a `PasswordStrength` enum.
pub fn check_password_strength(password: &str) -> Result<PasswordStrength, String> {
    if password.is_empty() {
        return Err(String::from("Password must contain min 1 char"));
    }
    let entropy = calculate_entropy(password);
    let mut score = 0;

    if entropy < 40.0 {
        return Ok(PasswordStrength::Weak);
    }

    match entropy {
        40.0..=59.9 => score += 0,
        60.0..=81.9 => score += 1,
        82.0..=99.9 => score += 2,
        _ => score += 3,
    }

    let has_common_words = check_has_common_words(password);

    if has_common_words && entropy < 85.0 {
        score -= 1;
    }

    match score {
        2..=3 => Ok(PasswordStrength::Strong),
        1 => Ok(PasswordStrength::Medium),
        _ => Ok(PasswordStrength::Weak),
    }
}

/// Calculates the entropy of a password.
///
/// # Arguments
///
/// * `password` - A string slice representing the password.
///
/// # Returns
///
/// The entropy of the password as a `f64`.
pub fn calculate_entropy(password: &str) -> f64 {
    let l = password.len() as f64;
    let mut r: f64 = 0.0;

    let password_specification = check_password_specification(&password);

    if password_specification.has_lowercase {
        r += LOWERCASE_CHARSET.len() as f64;
    }
    if password_specification.has_uppercase {
        r += UPPERCASE_CHARSET.len() as f64;
    }
    if password_specification.has_number {
        r += NUMBERS.len() as f64;
    }
    if password_specification.has_special {
        r += SPECIAL_CHARSET.len() as f64;
    }

    l * r.log2()
}

/// Replaces a character in a password with a random character from a given set.
///
/// # Arguments
///
/// * `password` - A mutable string reference to the password.
/// * `set` - A string slice representing the set of characters to use.
/// * `rng_thread` - A mutable reference to a thread random number generator.
fn replace_char(password: &mut String, set: &str, rng_thread: &mut rand::prelude::ThreadRng) {
    let index = rng_thread.gen_range(0..password.len());
    let char_to_add = set.chars().nth(rng_thread.gen_range(0..set.len())).unwrap();
    password.replace_range(index..=index, &char_to_add.to_string());
}

/// Removes whitespace from a string.
///
/// # Arguments
///
/// * `input` - A string slice representing the input.
///
/// # Returns
///
/// A string with all whitespace removed.
fn remove_whitespace(input: &str) -> String {
    input.split_whitespace().collect()
}

/// Checks if a password contains common words.
///
/// # Arguments
///
/// * `password` - A string slice representing the password.
///
/// # Returns
///
/// `true` if the password contains common words, `false` otherwise.
fn check_has_common_words(password: &str) -> bool {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("dictionary.txt");
    let contents = fs::read_to_string(path).expect("Cannot read file.");
    let words: Vec<&str> = contents.lines().collect();

    for word in words {
        if password.contains(&word) {
            return true;
        }
    }

    false
}

/// Checks the specification of a password.
///
/// # Arguments
///
/// * `password` - A string slice representing the password.
///
/// # Returns
///
/// A `PasswordSpecification` structure containing the specifications of the password.
fn check_password_specification(password: &str) -> PasswordSpecification {
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_number = password.chars().any(|c| c.is_digit(10));
    let has_special = password.chars().any(|c| SPECIAL_CHARSET.contains(c));

    PasswordSpecification {
        has_lowercase,
        has_uppercase,
        has_number,
        has_special,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_with_default() {
        let options = PasswordOptions::default();

        let result = options.generate_password();
        assert!(result.is_ok());
        let password = result.unwrap();
        assert_eq!(password.len(), PasswordOptions::default().length);

        assert!(matches!(check_password_strength(&password).unwrap(), PasswordStrength::Strong));
    }

    #[test]
    fn test_generate_password_length_too_short() {
        let options = PasswordOptions {
            length: 5,
            ..Default::default()
        };

        let result = options.generate_password();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Password length less than 10 is considered weak.");
    }

    #[test]
    fn test_generate_password() {
        let options = PasswordOptions {
            length: 15,
            ..Default::default()
        };

        let result = options.generate_password();
        let password = result.unwrap();
        assert_eq!(password.len(), 15);
        assert!(matches!(check_password_strength(&password).unwrap(), PasswordStrength::Strong));
        assert!(password.chars().any(|c| LOWERCASE_CHARSET.contains(c)));
        assert!(password.chars().any(|c| UPPERCASE_CHARSET.contains(c)));
        assert!(password.chars().any(|c| NUMBERS.contains(c)));
        assert!(password.chars().any(|c| SPECIAL_CHARSET.contains(c)));
    }

    #[test]
    fn test_generate_password_from_phrase() {
        let options = PasswordOptions {
            phrase: Some("a".to_string()),
            ..Default::default()
        };

        let password = options.generate_password();
        assert_eq!(password.unwrap(), "a".repeat(PasswordOptions::default().length));
    }

    #[test]
    fn test_balance_password() {
        let mut password = "qwertyuiop".to_string();
        assert!(matches!(check_password_strength(&password).unwrap(), PasswordStrength::Weak));

        let balanced = balance_password(&mut password);
        assert!(matches!(check_password_strength(&balanced).unwrap(), PasswordStrength::Strong));
    }

    #[test]
    fn test_check_password_strength() {
        assert!(matches!(check_password_strength("!QEa4Kta2}wg1").unwrap(), PasswordStrength::Strong));
        assert!(matches!(check_password_strength("Medium333!@").unwrap(), PasswordStrength::Medium));
        assert!(matches!(check_password_strength("weakpassword").unwrap(), PasswordStrength::Weak));
    }
}
