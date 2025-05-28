use std::fs;

pub fn read_file(path: &str) -> Result<String, std::io::Error> {
    fs::read_to_string(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_file() {
        let path = "test.txt";
        fs::write(path, "Hello, world!").unwrap(); //#[allow_ci]
        let content = read_file(path).unwrap(); //#[allow_ci]
        assert_eq!(content, "Hello, world!");
        fs::remove_file(path).unwrap(); //#[allow_ci]
    }

    #[test]
    fn test_read_nonexistent_file() {
        let result = read_file("nonexistent.txt");
        assert!(result.is_err());
    }
}
