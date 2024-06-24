use rand::{thread_rng, Rng};

pub struct PasswordOptions {
    pub length:Option<u32>,
    pub include_special_chars:Option<bool>,
    pub include_uppercase:Option<bool>,
    pub include_numbers:Option<bool>,
    pub with_balancing:Option<bool>,
    pub phrase:Option<String>
}
    
    const UPPERCASE_CHARSET: &str = "QWERTYUIOPASDFGHJKLZXCVBNM";
    const LOWERCASE_CHARSET: &str = "qwertyuiopasdfghjklzxcvbnm";
    const NUMBERS: &str = "1234567890";
    const SPECIAL_CHARSET:&str = "!@#$%^&*()-=_+{}[]<>?";

    pub fn generate_random_password(charset: &str, length: u32) -> String {
        let mut rng_thread = thread_rng();
        (0..length)
            .map(|_| {
                let index = rng_thread.gen_range(0..charset.len());
                charset.chars().nth(index).unwrap()
            })
            .collect()
    }
    
    pub fn generate_password(options:Option<PasswordOptions>) -> String {
        let default_options = PasswordOptions {
            length: Some(12),
            include_special_chars: Some(true),
            include_uppercase: Some(true),
            include_numbers: Some(true),
            with_balancing: Some(true),
            phrase: None,
        };

        let options = options.unwrap_or(default_options);
        let length = options.length.unwrap_or(10);
        if length < 10 {
           return String::from("Password length less than 10 is considered weak.")
        }

        let charset = generate_charset(&options);

        let mut password:String = generate_random_password(&charset, length);

        if options.phrase.is_none() && options.with_balancing.unwrap_or(true) {
            balance_password(&mut password, &options);
        }


        password
    }

    pub fn balance_password(password:&mut String, options:&PasswordOptions) {
        let mut rng_thread = thread_rng();
        let password_length:usize = options.length.unwrap_or(12) as usize;

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
    
            if !options.include_uppercase.unwrap_or(false) {
                has_uppercase = true;
            }
            if !options.include_numbers.unwrap_or(false) {
                has_number = true;
            }
            if !options.include_special_chars.unwrap_or(false) {
                has_special = true;
            }

    
            if  has_uppercase && has_number && has_special && has_lowercase {
                break;
            }

            if !has_lowercase  {
                replace_char(password, LOWERCASE_CHARSET, &mut rng_thread);
            }
            if !has_uppercase && options.include_uppercase.unwrap_or(false) {
                replace_char(password, UPPERCASE_CHARSET, &mut rng_thread);
            }
            if !has_number && options.include_numbers.unwrap_or(false) {
                replace_char(password, NUMBERS, &mut rng_thread);
            }
            if !has_special && options.include_special_chars.unwrap_or(false) {
                replace_char(password, SPECIAL_CHARSET, &mut rng_thread);
            }
        }
    }

    pub fn check_password_strength(password:&str) -> &str {
        let mut score = 0;
        let password_length = password.len();

        if password_length >= 12 {
            score += 2;
        } else if password_length >= 10 {
            score +=1;
        }

        if password.chars().any(|c| c.is_lowercase()) {
            score += 2;
        }

        if password.chars().any(|c| c.is_uppercase()) {
            score += 2;
        }

        if password.chars().any(|c| c.is_digit(10)) {
            score += 2;
        }

        if password.chars().any(|c| SPECIAL_CHARSET.contains(c)) {
            score += 2;
        }

        match score {
            10 => "Strong",
            7..=9 => "Medium",
            _ => "Weak",
        }
    }

     fn generate_charset(options:&PasswordOptions) -> String {
        let mut charset = String::from("");

        if let Some(existed_phrase) = &options.phrase {
            charset.push_str(&remove_whitespace(existed_phrase));
        } else {
            charset.push_str(LOWERCASE_CHARSET);
            if options.include_uppercase.unwrap_or(false) {
                charset.push_str(UPPERCASE_CHARSET);
            }
            if options.include_numbers.unwrap_or(false) {
                charset.push_str(NUMBERS);
            }
            if options.include_special_chars.unwrap_or(false) {
                charset.push_str(SPECIAL_CHARSET);
            }
        }

        charset
    } 

    fn replace_char(password: &mut String, set: &str, rng_thread: &mut rand::prelude::ThreadRng) {
        let index = rng_thread.gen_range(0..password.len());
        let replace_char = set.chars().nth(rng_thread.gen_range(0..set.len())).unwrap();
        password.replace_range(index..=index, &replace_char.to_string());
    }
    

    fn remove_whitespace(input: &String) -> String {
        input.split_whitespace().collect()
    }


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_without_args() {
    
      let password = generate_password(None);
      assert_eq!(password.len(), 12);
      assert_eq!(check_password_strength(&password), "Strong");
    }

    #[test]
    fn test_generate_password() {
        let options = PasswordOptions {
            length: Some(15),
            include_special_chars: Some(true),
            include_uppercase: Some(true),
            include_numbers: Some(true),
            with_balancing: Some(true),
            phrase: None,
        };
    
      let password = generate_password(Some(options));
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
            length: Some(12),
            include_special_chars: Some(true),
            include_uppercase: Some(true),
            include_numbers: Some(true),
            with_balancing: Some(true),
            phrase: Some("a".to_string()),
        };
    
      let password = generate_password(Some(options));
      assert_eq!(password, "aaaaaaaaaaaa");
    }

    #[test]
    fn test_balance_password() {
        let options = PasswordOptions {
            length: Some(12),
            include_special_chars: Some(true),
            include_uppercase: Some(true),
            include_numbers: Some(true),
            with_balancing: Some(true),
            phrase: None,
        };
     let mut password = "qwertyuiop".to_string();
     assert_eq!(check_password_strength(&password), "Weak");

     balance_password(&mut password, &options);
     assert_eq!(check_password_strength(&password), "Strong");
    }
    
    
    #[test]
    fn test_check_password_strength() {
        assert_eq!(check_password_strength("StrongP@ssword123!"), "Strong");
        assert_eq!(check_password_strength("MediumPass123"), "Medium");
        assert_eq!(check_password_strength("weakpassword"), "Weak");
    }
}