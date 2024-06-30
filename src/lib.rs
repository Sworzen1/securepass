use rand::seq::IteratorRandom;
use rand::{thread_rng, Rng};
use std::fs;
use std::path::Path;

pub struct PasswordOptions {
    // You should usually use usize, not sure why you did not
    pub length: usize,
    pub include_special_chars: bool,
    pub include_uppercase: bool,
    pub include_numbers: bool,
    pub with_balancing: bool,
    pub phrase: Option<String>,
}

const UPPERCASE_CHARSET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARSET: &str = "abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &str = "0123456789";
const SPECIAL_CHARSET: &str = "!@#$%^&*?(){}[]<>-_=+";

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 12,
            include_special_chars: true,
            include_uppercase: true,
            include_numbers: true,
            with_balancing: true,
            phrase: None,
        }
    }
}

impl PasswordOptions {
    pub fn generate_password(&self) -> String {
        let length = self.length;
        if length < 10 {
            // This is weird behavior? you would expect a password back but instead you get a string containing an error. 
            // It is best to use a result type or offer some type of warning system. Its inconsistent and makes it hard to use lib.
            return String::from("Password length less than 10 is considered weak.");
        }
        let charset = self.generate_charset();

        let mut password: String = generate_random_password(&charset, length);

        if self.phrase.is_none() && self.with_balancing {
            password = self.balance_password(&mut password);
        }

        password
    }

    pub fn balance_password(&self, password: &mut String) -> String {
        // Maybe make this optional?
        let mut password = remove_dictionary_words(password);
        let mut rng_thread = thread_rng();
        let password_length: usize = self.length as usize;

        if password.len() < password_length {
            // Im really confused here, why are you using a different charset. You made a method 
            // to create a charset for you that fits the specifications yet you create a broad one.???
            // let charset = format!(
            //     "{}{}{}{}",
            //     UPPERCASE_CHARSET, LOWERCASE_CHARSET, NUMBERS, SPECIAL_CHARSET
            // );
            // I changed it to this as it made more sense
            let charset = self.generate_charset();

            let num_chars_to_add = password_length - password.len();
            let str_to_add = generate_random_password(&charset, num_chars_to_add);
            password.push_str(&str_to_add);
        }
        // ^^^ All this above should be its own function as it does a lot of unexpected things. 
        // I would expect balance password to apply the rule config onto the password but it kinda goes against the rules and confuses me. 
        // You can clarify this choice if you wish.


        // This loop is very unclear with its variable naming, because you create a new charset that defies the users wanted password it 
        // just creates unnecessary computation here
        // This is kinda dangerous as there might be a case where it run indefinitely maybe better solutions should be looked at
        loop {
            let pass_before = password.clone();
            if self.include_uppercase && !password.chars().any(|c| c.is_uppercase()) {
                replace_char(&mut password, UPPERCASE_CHARSET, &mut rng_thread);
            }
            if self.include_numbers && !password.chars().any(|c| c.is_digit(10)) {
                replace_char(&mut password, NUMBERS, &mut rng_thread);
            }
            if self.include_special_chars && !password.chars().any(|c| SPECIAL_CHARSET.contains(c)) {
                replace_char(&mut password, SPECIAL_CHARSET, &mut rng_thread);
            }
            if !password.chars().any(|c| c.is_lowercase()) {
                replace_char(&mut password, LOWERCASE_CHARSET, &mut rng_thread);
            }

            if pass_before == password {
                break;
            }
        }

        password
    }

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

/// Generates a random password given a length and charset
// Best to use usize when specifying indices or lengths
pub fn generate_random_password(charset: &str, length: usize) -> String {
    charset.chars().choose_multiple(&mut rand::thread_rng(), length).into_iter().collect()
}

/// Calculates passwords strength score and assigns it a strength label in form of &str
pub fn check_password_strength(password: &str) -> &str {
    let initial_length = password.len();
    let password = remove_dictionary_words(password);

    let mut score = match password.len() {
        0..=7 => 0,
        8..=11 => 1,
        _ => 2,
    };

    let criteria = [
        password.chars().any(|c| c.is_lowercase()),
        password.chars().any(|c| c.is_uppercase()),
        password.chars().any(|c| c.is_digit(10)),
        password.chars().any(|c| SPECIAL_CHARSET.contains(c)),
    ];
    score += criteria.into_iter().filter(|a| *a).count();

    score += match initial_length {
        0..=9 => 0,
        10..=17 => 1,
        _ => 2,
    };
    // If im really being picky its best for this to be an enum as there can only be three states
    match score {
        0..=3 => "Weak",
        4..=6 => "Medium",
        _ => "Strong",
    }
}

/// Replaces a random char within password with a random one from the charset
fn replace_char(password: &mut String, set: &str, rng_thread: &mut rand::prelude::ThreadRng) {
    let index = rng_thread.gen_range(0..password.len());

    let replace_char = set.chars().choose(rng_thread).unwrap();

    password.replace_range(index..=index, &replace_char.to_string());
}

fn remove_whitespace(input: &str) -> String {
    input.split_whitespace().collect()
}

/// Removes any words contained within dictionary.txt as they are problematic
fn remove_dictionary_words(password: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("dictionary.txt");

    let contents = fs::read_to_string(path).expect("Unable to read dictionary.txt"); // Just reading one file

    let mut password = String::from(password);

    for word in contents.lines() {
        if password.contains(word) {
            password = password.replace(word, "");
        }
    }

    password
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_with_default() {
        let options = PasswordOptions::default();

        let password = options.generate_password();
        assert_eq!(password.len(), 12);
        assert_eq!(check_password_strength(&password), "Strong");
    }

    #[test]
    fn test_generate_password() {
        let options = PasswordOptions {
            length: 15,
            ..Default::default()
        };

        let password = options.generate_password();
        assert_eq!(password.len(), 15);
        assert_eq!(check_password_strength(&password), "Strong");
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
        assert_eq!(password, "aaaaaaaaaaaa");
    }

    #[test]
    fn test_balance_password() {
        let options = PasswordOptions::default();
        let mut password = "qwertyuiop".to_string();
        assert_eq!(check_password_strength(&password), "Weak");

        let balanced = options.balance_password(&mut password);
        assert_eq!(check_password_strength(&balanced), "Strong");
    }

    #[test]
    fn test_check_password_strength() {
        assert_eq!(check_password_strength("!QEa4Kta2}wg"), "Strong");
        assert_eq!(check_password_strength("Medium123!9"), "Medium");
        assert_eq!(check_password_strength("weakpassword"), "Weak");
    }
}
