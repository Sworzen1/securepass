use rand::{thread_rng, Rng};
use std::fs;
use std::path::Path;

pub struct PasswordSpecification {
    pub has_lowercase:bool,
    pub has_uppercase:bool,
    pub has_special:bool,
    pub has_number:bool,
}

pub enum PasswordStrength {
    Weak,
    Medium,
    Strong
}
pub struct PasswordOptions {
    pub length:usize,
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
        pub fn generate_password(&self) -> Result<String, String> {
            let length = self.length;
            if length < 10 {
               return Err(String::from("Password length less than 10 is considered weak."))
            }
            let charset = self.generate_charset();
    
            let mut password:String = generate_random_password(&charset, length);
    
            if self.phrase.is_none() && self.with_balancing {
                password = balance_password(&mut password);
            }
    
    
            Ok(password)
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

    pub fn generate_random_password(charset: &str, length: usize) -> String {
        let mut rng_thread = thread_rng();
        (0..length)
            .map(|_| {
                let index = rng_thread.gen_range(0..charset.len());
                charset.chars().nth(index).unwrap()
            })
            .collect()
    }

    pub fn balance_password(password:&mut String) -> String {
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
            let password_str = check_password_strength(password);
            let password_specification = check_password_specification(password);

            if let PasswordStrength::Strong = password_str {
                if password_specification.has_lowercase
                && password_specification.has_number
                && password_specification.has_special
                && password_specification.has_uppercase {
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
    
    
    pub fn check_password_strength(password:&str) -> PasswordStrength {
        let entropy = calculate_entropy(password);
        let mut score = 0;
        
        if entropy < 40.0 {
            return PasswordStrength::Weak;
        }
            
        match entropy {
            40.0..=59.9 => score += 0,
            60.0..=81.9 => score += 1,
            82.0..=99.9 => score += 2,
            _ => score += 3
        }
                
        let has_common_words = check_has_common_words(password);

        if has_common_words && entropy < 85.0 {
            score -= 1;
        }

        match score {
            2..=3 => PasswordStrength::Strong,
            1 => PasswordStrength::Medium,
            _ => PasswordStrength::Weak,
        }
    }

     // entropy = L * log2(R)
    // L = password length
    // R = number of characters in set to use
    pub fn calculate_entropy(password:&str) -> f64 {
        let l = password.len() as f64;
        let mut r:f64 = 0.0;

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

    fn replace_char(password: &mut String, set: &str, rng_thread: &mut rand::prelude::ThreadRng) {
        let index = rng_thread.gen_range(0..password.len());
        let char_to_add = set.chars().nth(rng_thread.gen_range(0..set.len())).unwrap();
        password.replace_range(index..=index, &char_to_add.to_string());
    }
    

    fn remove_whitespace(input: &str) -> String {
        input.split_whitespace().collect()
    }


    fn check_has_common_words(password: &str) -> bool {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("dictionary.txt");
        let contents = fs::read_to_string(path).expect("Can not read files.");
        let words: Vec<&str> = contents.lines().collect();

        for word in words {
            if password.contains(&word) {
                return true;
            }
        }

        false
    }

    fn check_password_specification (password: &str) -> PasswordSpecification {
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

        assert!(matches!(check_password_strength(&password), PasswordStrength::Strong));
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
        assert!(matches!(check_password_strength(&password), PasswordStrength::Strong));
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
        assert!(matches!(check_password_strength(&password), PasswordStrength::Weak));

        let balanced = balance_password(&mut password);
        assert!(matches!(check_password_strength(&balanced), PasswordStrength::Strong));
    }
    
    
    #[test]
    fn test_check_password_strength() {
        assert!(matches!(check_password_strength("!QEa4Kta2}wg1"), PasswordStrength::Strong));
        assert!(matches!(check_password_strength("Medium333!@"), PasswordStrength::Medium));
        assert!(matches!(check_password_strength("weakpassword"), PasswordStrength::Weak));
    }
}