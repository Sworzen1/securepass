use rand::{thread_rng, Rng};
use std::fs;
use std::path::Path;

pub struct PasswordOptions {
    pub length:u32,
    pub include_special_chars:bool,
    pub include_uppercase:bool,
    pub include_numbers:bool,
    pub with_balancing:bool,
    pub phrase:Option<String>
}
    
    const UPPERCASE_CHARSET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWERCASE_CHARSET: &str = "abcdefghijklmnopqrstuvwxyz";
    const NUMBERS: &str = "0123456789";
    const SPECIAL_CHARSET:&str = "!@#$%^&*?(){}[]<>-_=+";

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
               return String::from("Password length less than 10 is considered weak.")
            }
            let charset = self.generate_charset();
    
            let mut password:String = generate_random_password(&charset, length);
    
            if self.phrase.is_none() && self.with_balancing {
                password = self.balance_password(&mut password);
            }
    
    
            password
        }
    
        pub fn balance_password(&self, password:&mut String) -> String {
            let mut password = check_password_in_dictionary(password);
            let mut rng_thread = thread_rng();
            let password_length:usize = self.length as usize;
    
            if password.len() < password_length {
                let charset = format!("{}{}{}{}", UPPERCASE_CHARSET, LOWERCASE_CHARSET, NUMBERS, SPECIAL_CHARSET);
                let num_chars_to_add = (password_length - password.len()) as u32;
                let str_to_add = generate_random_password(&charset, num_chars_to_add);
                password.push_str(&str_to_add);
            }

            loop {
                let has_lowercase = password.chars().any(|c| c.is_lowercase());
                let mut has_uppercase = password.chars().any(|c| c.is_uppercase());
                let mut has_number = password.chars().any(|c| c.is_digit(10));
                let mut has_special = password.chars().any(|c| SPECIAL_CHARSET.contains(c));
        
                if !self.include_uppercase {
                    has_uppercase = true;
                }
                if !self.include_numbers {
                    has_number = true;
                }
                if !self.include_special_chars {
                    has_special = true;
                }
    
        
                if  has_uppercase && has_number && has_special && has_lowercase {
                    break;
                }
    
                if !has_lowercase  {
                    replace_char(&mut password, LOWERCASE_CHARSET, &mut rng_thread);
                }
                if !has_uppercase && self.include_uppercase {
                    replace_char(&mut password, UPPERCASE_CHARSET, &mut rng_thread);
                }
                if !has_number && self.include_numbers {
                    replace_char(&mut password, NUMBERS, &mut rng_thread);
                }
                if !has_special && self.include_special_chars {
                    replace_char(&mut password, SPECIAL_CHARSET, &mut rng_thread);
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

    pub fn generate_random_password(charset: &str, length: u32) -> String {
        let mut rng_thread = thread_rng();
        (0..length)
            .map(|_| {
                let index = rng_thread.gen_range(0..charset.len());
                charset.chars().nth(index).unwrap()
            })
            .collect()
    }
    
    

    pub fn check_password_strength(password:&str) -> &str {
        let initial_length = password.len();
        let password = check_password_in_dictionary(password);

        let mut score = 0;
        let password_length = password.len();

        match password_length {
            len if len >= 12 => score = 2,
            8..=11 => score = 1,
            _=> score = 0,
        }

        if password.chars().any(|c| c.is_lowercase()) {
            score += 1;
        }

        if password.chars().any(|c| c.is_uppercase()) {
            score += 1;
        }

        if password.chars().any(|c| c.is_digit(10)) {
            score += 1;
        }

        if password.chars().any(|c| SPECIAL_CHARSET.contains(c)) {
            score += 1;
        }

        match initial_length {
            len if len >= 18 => score += 2,
            10..=17 => score += 1,
            _ => score+=0
        }

        match score {
            7..8 => "Strong",
            4..=6 => "Medium",
            _ => "Weak",
        }
    }

    fn replace_char(password: &mut String, set: &str, rng_thread: &mut rand::prelude::ThreadRng) {
        let index = rng_thread.gen_range(0..password.len());
        let replace_char = set.chars().nth(rng_thread.gen_range(0..set.len())).unwrap();
        password.replace_range(index..=index, &replace_char.to_string());
    }
    

    fn remove_whitespace(input: &str) -> String {
        input.split_whitespace().collect()
    }

    fn check_password_in_dictionary(password: &str) -> String {
        let mut password = String::from(password);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dictionary.txt");
        let contents = fs::read_to_string(path).expect("Can not read files.");
        let words: Vec<&str> = contents.lines().collect();

        for word in words {
            let word_str = word;
            if  password.contains(&word_str) {
                password = password.replace(&word_str, "");
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