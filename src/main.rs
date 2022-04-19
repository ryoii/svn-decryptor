use std::{env, fs, ptr};
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::wincrypt::DATA_BLOB;
use std::collections::{hash_map, HashMap};

fn main() {
    let app_data_fold = env::var_os("APPDATA")
        .expect("Can't find environment value: APPDATA")
        .into_string()
        .expect("Can't find environment value: APPDATA");

    let auth_fold = app_data_fold + "\\Subversion\\auth\\svn.simple";

    let dir = fs::read_dir(&auth_fold)
        .expect("Can't find or open subversion data fold");

    for path in dir {
        let data = fs::read_to_string(path.unwrap().path())
            .expect(&*format!("Read file failed in {}", &auth_fold));

        let auth_file = AuthFile::from_raw_context(&data);
        let password = decrypt(auth_file.password());

        println!("{}\r\n{}", auth_file.username(), password);
    }

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
    fn from_raw_context(context: &str) -> AuthFile {
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
                        assert_eq!(_t, "K", "Unexpect data format.");
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
                    assert_eq!(_t, "V", "Unexpect data format.");
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

        AuthFile { opt }
    }

    fn parse_def_line(line: &str) -> (&str, usize) {
        let mut split = line.split(" ");
        let t = split.next().expect("");
        let len = split.next().expect("");
        let len = len.parse::<usize>().expect("");
        return (t, len);
    }

    fn username(&self) -> &str {
        self.opt.get("username").unwrap()
    }

    fn password(&self) -> &str {
        self.opt.get("password").unwrap()
    }
}

fn decrypt(encrypted: &str) -> String {
    let mut raw_data = base64::decode(encrypted)
        .expect("Invalid data input.");

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
        panic!("Decrypt failed. Run this program in the correct machine.")
    }

    let decrypted = unsafe {
        String::from_raw_parts(
            data_out.pbData,
            data_out.cbData as usize,
            data_out.cbData as usize)
    };

    return decrypted;
}