use std::{env, fs, ptr};
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::wincrypt::DATA_BLOB;
use std::collections::{hash_map, HashMap};
use std::io::{Read, Write};
use anyhow::{anyhow, Result};

macro_rules! ok_or_continue {
    ($expr:expr) => {
        match $expr {
            Result::Ok(v) => v,
            Result::Err(_) => continue,
        }
    };
}

fn main() -> Result<()> {
    let app_data_fold = env::var_os("APPDATA")
        .ok_or(anyhow!("Can't find environment value: APPDATA"))?
        .into_string().unwrap();

    let auth_fold = app_data_fold + "\\Subversion\\auth\\svn.simple";

    let dir = fs::read_dir(&auth_fold)?;
    let mut res = Vec::new();

    for path in dir {
        let path = path?;
        if path.metadata()?.is_dir() {
            continue;
        }

        let data = ok_or_continue!(fs::read_to_string(path.path()));
        let auth_file = ok_or_continue!(AuthFile::from_raw_context(&data));
        let username = ok_or_continue!(auth_file.username());
        let password = ok_or_continue!(auth_file.password());
        let password = ok_or_continue!(decrypt(password));

        res.push((String::from(username), password));
    };

    if res.is_empty() {
        println!("No auth file found.");
    } else {
        for (username, password) in res {
            println!("{}\r\n{}", username, password);
        }
    }

    print!("Press any key to continue...");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read(&mut [0u8]).unwrap();
    Ok(())
}

#[derive(Debug)]
struct AuthFile {
    opt: hash_map::HashMap<String, String>,
}

#[derive(Copy, Clone)]
enum State {
    KeyDef,
    KeyValue,
    ValueDef,
    ValValue,
}

impl AuthFile {
    fn from_raw_context(context: &str) -> Result<AuthFile> {
        let lines = context.lines();
        let mut opt = HashMap::new();
        let mut len = 0usize;
        let mut key = "";
        let mut state = State::KeyDef;

        for line in lines {
            state = match state {
                State::KeyDef => match line {
                    "END" => break,
                    _ => {
                        let (_t, l) = Self::parse_def_line(line);
                        if _t != "K" {
                            return Err(anyhow!("Unexpect data format."));
                        };
                        len = l;
                        State::KeyValue
                    }
                }
                State::KeyValue => {
                    key = &line[..len];
                    State::ValueDef
                }
                State::ValueDef => {
                    let (_t, l) = Self::parse_def_line(line);
                    if _t != "V" {
                        return Err(anyhow!("Unexpect data format."));
                    }
                    len = l;
                    State::ValValue
                }
                State::ValValue => {
                    let v = &line[..len];
                    opt.insert(String::from(key), String::from(v));
                    State::KeyDef
                }
            }
        };

        Ok(AuthFile { opt })
    }

    fn parse_def_line(line: &str) -> (&str, usize) {
        let mut split = line.split(" ");
        let t = split.next().unwrap_or("");
        let len = split.next().unwrap_or("");
        let len = len.parse::<usize>().unwrap_or(0);
        return (t, len);
    }

    fn username(&self) -> Result<&String> {
        self.opt.get("username").ok_or(anyhow!("Can't found username"))
    }

    fn password(&self) -> Result<&String> {
        self.opt.get("password").ok_or(anyhow!("Can't found password"))
    }
}

fn decrypt(encrypted: &str) -> Result<String> {
    let mut raw_data = base64::decode(encrypted)?;

    let mut data_in = DATA_BLOB {
        cbData: raw_data.len() as u32,
        pbData: raw_data.as_mut_ptr(),
    };
    let mut data_out = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let res = unsafe {
        CryptUnprotectData(
            &mut data_in,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0x1,
            &mut data_out,
        ) as u8
    };
    if res == 0 {
        return Err(anyhow!("Decrypt failed. Run this program in the correct machine."));
    }

    let decrypted = unsafe {
        String::from_raw_parts(
            data_out.pbData,
            data_out.cbData as usize,
            data_out.cbData as usize)
    };

    return Ok(decrypted);
}