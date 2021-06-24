// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use super::*;
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::env;
use std::process::Command;
use std::process::Output;
use std::str;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

const MAX_TRY: usize = 10;
const RETRY_SLEEP: Duration = Duration::from_millis(50);
const TPM_IO_ERROR: i32 = 5;
const RETRY: usize = 4;

/*
 * Input:
 *     command: command to be executed
 *     output_path: file output location
 * return:
 *     execution return output and file output
 *     KeylimeTpmError
 *
 * Set up execution envrionment to execute tpm command through shell commands
 * and return the execution result in a tuple. Based on the latest update of
 * python keylime this function implement the functionality of cmd_exec
 * script in the python keylime repo. RaiseOnError, return code and lock are
 * dropped due to different error handling in Rust. Returned output string are
 * preprocessed to before returning for code efficient.
 */
pub(crate) fn run(
    command: String,
    output_path: Option<&str>,
) -> Result<(String, String)> {
    let mut file_output = String::new();
    let mut output: Output;

    // tokenize input command
    let words: Vec<&str> = command.split(' ').collect();
    let mut number_tries = 0;
    let args = &words[1..words.len()];
    let cmd = &words[0];

    // setup environment variable
    let mut env_vars: HashMap<String, String> = HashMap::new();
    for (key, value) in env::vars() {
        let _ = env_vars.insert(key.to_string(), value.to_string());
    }
    let _ =
        env_vars.insert("TPM_SERVER_PORT".to_string(), "9998".to_string());
    let _ = env_vars
        .insert("TPM_SERVER_NAME".to_string(), "localhost".to_string());
    match env_vars.get_mut("PATH") {
        Some(v) => v.push_str(TPM_TOOLS_PATH),
        None => {
            return Err(Error::Configuration(
                "PATH environment variable doesn't exist".to_string(),
            ));
        }
    }

    // main loop
    'exec: loop {
        // Start time stamp
        let t0 = SystemTime::now();

        output = Command::new(&cmd).args(args).envs(&env_vars).output()?;

        // measure execution time
        let t_diff = t0
            .duration_since(t0)
            .unwrap_or_else(|_| Duration::new(0, 0));
        info!("Time cost: {}", t_diff.as_secs());

        // assume the system is linux
        info!("Number tries: {:?}", number_tries);

        match output.status.code() {
            Some(TPM_IO_ERROR) => {
                number_tries += 1;
                if number_tries >= MAX_TRY {
                    return Err(Error::TpmInUse);
                }

                info!(
                    "Failed to call TPM {}/{} times, trying again in {} secs.",
                    number_tries,
                    MAX_TRY,
                    RETRY,
                );

                thread::sleep(RETRY_SLEEP);
            }

            _ => break 'exec,
        }
    }

    let return_output = String::from_utf8(output.stdout)?;
    if output.status.success() {
        info!("Successfully executed TPM command");
    } else {
        return Err(Error::Execution(output.status.code(), return_output));
    }

    // Retrive data from output path file
    if let Some(p) = output_path {
        file_output = read_file_output_path(p.to_string())?;
    }

    Ok((return_output, file_output))
}

/*
 * Input: file name
 * Return: the content of the file int Result<>
 *
 * run method helper method
 * read in the file and  return the content of the file into a Result enum
 */
fn read_file_output_path(output_path: String) -> std::io::Result<String> {
    let mut file = File::open(output_path)?;
    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents)?;
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_file_output_path() {
        assert_eq!(
            read_file_output_path("test-data/test_input.txt".to_string())
                .unwrap(), //#[allow_ci]
            "Hello World!\n"
        );
    }

    #[test]
    fn test_run_command() {
        match command_exist("getrandom") {
            true => {
                let command = "getrandom -size 8 -out foo.out".to_string();
                run(command, None);
                let p = Path::new("foo.out");
                assert!(p.exists());
                let _ = fs::remove_file("foo.out");
            }
            false => {}
        }
    }
    /*
     * Input: command name
     * Output: checkout command result
     *
     * Look for the command in path, if command is there return true, if
     * command is not exist return false.
     */
    fn command_exist(command: &str) -> bool {
        if let Ok(path) = env::var("PATH") {
            for pp in path.split(':') {
                let command_path = format!("{}/{}", pp, command);
                if fs::metadata(command_path).is_ok() {
                    return true;
                }
            }
        }
        false
    }
}
