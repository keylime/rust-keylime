use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::{self, Debug, Display};

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonWrapper<A> {
    pub code: u16,
    pub status: String,
    pub results: A,
}

impl JsonWrapper<Value> {
    pub fn error(code: u16, status: impl ToString) -> JsonWrapper<Value> {
        JsonWrapper {
            code,
            status: status.to_string(),
            results: json!({}),
        }
    }
}

impl<'de, A> JsonWrapper<A>
where
    A: Deserialize<'de> + Serialize + Debug,
{
    pub fn success(results: A) -> JsonWrapper<A> {
        JsonWrapper {
            code: 200,
            status: String::from("Success"),
            results,
        }
    }
}

impl<'de, A> Display for JsonWrapper<A>
where
    A: Deserialize<'de> + Serialize + Debug + Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let out = json!(self).to_string();
        write!(f, "{}", out)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestResult {
        result: String,
    }

    impl Display for TestResult {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let out = json!(self).to_string();
            write!(f, "{}", out)
        }
    }

    #[test]
    fn test_json_wrapper_success() {
        let expected = json!({
            "code": 200,
            "status": "Success",
            "results": TestResult{
                result: "Success".to_string(),
            },
        });
        let j = JsonWrapper::success(TestResult {
            result: "Success".to_string(),
        });
        assert_eq!(j.to_string(), expected.to_string());
    }

    #[test]
    fn test_json_wrapper_error() {
        let expected = json!({
            "code": 400,
            "status": "Testing JsonWrapper error",
            "results": {},
        });
        let j =
            JsonWrapper::error(400, "Testing JsonWrapper error".to_string());
        assert_eq!(j.to_string(), expected.to_string());
    }
}
