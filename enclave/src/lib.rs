// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "filesampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
#[macro_use]
extern crate sgx_rand_derive;
extern crate sgx_serialize;
#[macro_use]
extern crate sgx_serialize_derive;
extern crate sgx_tseal;
extern crate sgx_types;
// extern crate rand;

use sgx_types::sgx_status_t;
use std::sgxfs::SgxFile;
use std::io::{Read, Write, SeekFrom, Seek};
use std::str::from_utf8;
use std::string::String;
use std::sync::SgxMutex;
use std::string::ToString;
use sgx_tseal::{SgxSealedData};
use sgx_types::{sgx_sealed_data_t};
use sgx_serialize::{SerializeHelper, DeSerializeHelper};
use std::vec::Vec;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::os::raw::c_uchar;
use std::prelude::v1::*;
use std::ptr;
use std::cell::RefCell;
use std::rc::Rc;
use std::str;
use sgx_rand::Rng;

static EMAIL: SgxMutex<Option<String>> = SgxMutex::new(None);

//----------------------------HASHMAP-------------------------------
#[derive(Clone, Default, Debug, Serializable, DeSerializable)]
struct FileData {
    data: HashMap<String, String>,
}

#[no_mangle]
pub extern "C" fn ecall_pass_string(buf: *mut u8, max_buf_len: usize) -> i32 {
    let mut email = get_user_input();
    let str_len = email.len();
    if max_buf_len < str_len {
        return 1;
    }

    unsafe {
        let slice = std::slice::from_raw_parts_mut(buf, str_len);
        slice.copy_from_slice(email.as_bytes());
    }

    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut password = String::new();

    write!(stdout, "[+] Enter your password: ").unwrap();
    stdout.flush().unwrap();
    stdin.read_line(&mut password).unwrap();

    password = password.trim_end().to_string();
    email = email.trim_end().to_string();
    let mut data = [0_u8; 4096];

    // OPEN FILE
    let mut file = match SgxFile::open("creds") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::open failed.");
            return 1;
        },
    };

    // READ SIZE
    let read_size = match file.read(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::read failed.");
            return 2;
        },
    };

    // DECODING
    let DeserializeData = DeSerializeHelper::<FileData>::new(data.to_vec());
    let file_data = match DeserializeData.decode() {
        Some(d) => d,
        None => {
            println!("[FAIL] Decode data failed.");
            return 3;
        },
    };

    let mut actual_password = String::new();
    let mut actual_email = "";
    for (key, value) in &file_data.data {
        actual_email = key;
        let secret_key = String::from("my_secret_key");
        for (i, c) in value.chars().enumerate() {
            let key_char = secret_key.chars().nth(i % secret_key.len()).unwrap();
            let decrypted_char = (c as u8) ^ (key_char as u8);
            actual_password.push(decrypted_char as char);
        }
    }

    if actual_password == password && actual_email == email
    {
        drop(file);
        return 0;

    } else {
        drop(file);
        return 99;
    }
}


fn get_user_input() -> String {
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut buffer = String::new();

    write!(stdout, "[+] Enter your email: ").unwrap();
    stdout.flush().unwrap();
    stdin.read_line(&mut buffer).unwrap();

    buffer.trim_end().to_string()
}

//------------------------- WRITE FILE FUNCTION -----------------------
#[no_mangle]
pub extern "C" fn write_file() -> i32 {
    let mut key = String::new();
    let mut value = String::new();

    println!("[+] Enter a username:");
    std::io::stdin().read_line(&mut key).expect("[FAIL] Failed to read key");
    key = key.trim().to_string();

    println!("[+] Enter the password:");
    std::io::stdin().read_line(&mut value).expect("[FAIL] Failed to read value");
    value = value.trim().to_string();

    let mut file_data = match SgxFile::open("wallet") {
        Ok(mut f) => {
            let mut data = [0_u8; 4096];
            let read_size = match f.read(&mut data) {
                Ok(len) => len,
                Err(_) => {
                    println!("[FAIL] SgxFile::read failed.");
                    return 2;
                },
            };

            let DeserializeData = DeSerializeHelper::<FileData>::new(data.to_vec());
            match DeserializeData.decode() {
                Some(d) => d,
                None => {
                    println!("[FAIL] Decode data failed.");
                    return 3;
                },
            }
        }
        Err(_) => FileData {
            data: HashMap::new(),
        },
    };

    file_data.data.insert(key, value);

    let SerializeData = SerializeHelper::new();
    let data = match SerializeData.encode(&file_data) {
        Some(d) => d,
        None => {
            println!("[FAIL] Encode data failed.");
            return 4;
        },
    };

    let mut file = match SgxFile::create("wallet") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::create failed.");
            return 5;
        },
    };

    let write_size = match file.write(&data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::write failed.");
            return 6;
        },
    };

    0
}


//------------------------- READ FILE ------------------------------
#[no_mangle]
pub extern "C" fn read_file() -> i32 {
    // OPEN FILE
    let mut file = match SgxFile::open("wallet") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::open failed.");
            return 1;
        },
    };

    let mut data = Vec::new();
    let mut buffer = [0_u8; 4096];

    // READ FILE IN CHUNKS
    loop {
        match file.read(&mut buffer) {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    break; // End of file reached
                }
                data.extend_from_slice(&buffer[..bytes_read]);
            }
            Err(_) => {
                println!("[FAIL] SgxFile::read failed.");
                return 2;
            }
        }
    }

    // DECODING
    let DeserializeData = DeSerializeHelper::<FileData>::new(data);
    let file_data = match DeserializeData.decode() {
        Some(d) => d,
        None => {
            println!("[FAIL] Decode data failed.");
            return 3;
        },
    };

    for (key, value) in &file_data.data {
        println!("{} -> {}", key, value);
    }
    drop(file);
    return 99;
}


//-------------------------- ADD DATA ------------------------------
#[no_mangle]
pub extern "C" fn add_data() -> i32 {

    let mut data = [0_u8; 4096];

    // OPEN
    let mut file = match SgxFile::open("wallet") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::open failed.");
            return 1;
        },
    };

    // READ SIZE
    let read_size = match file.read(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::read failed.");
            return 2;
        },
    };

    // DECODE
    let DeserializeData = DeSerializeHelper::<FileData>::new(data.to_vec());
    let mut file_data = match DeserializeData.decode() {
        Some(d) => d,
        None => {
            println!("[FAIL]  Decode data failed.");
            return 3;
        },
    };

    drop(file);

    // TAKING ADDITIONAL INPUT
    let mut key = String::new();
    let mut value = String::new();

    println!("[+] Enter a new username:");
    std::io::stdin().read_line(&mut key).expect("[FAIL] Failed to read key");
    key = key.trim().to_string();

    println!("[+] Enter a password:");
    std::io::stdin().read_line(&mut value).expect("[FAIL] Failed to read value");
    value = value.trim().to_string();

    // INSERTING DATA INTO HASHMAP
    file_data.data.insert(key, value);

    // DECODING
    let SerializeData = SerializeHelper::new();
    let updated_data = match SerializeData.encode(&file_data) {
        Some(d) => d,
        None => {
            println!("[FAIL] Encode data failed.");
            return 4;
        },
    };

    let mut file = match SgxFile::create("wallet") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::create failed.");
            return 5;
        },
    };

    let write_size = match file.write(&updated_data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::write failed.");
            return 6;
        },
    };

    println!("[OK] Data addition completed successfully!");

    drop(file);

    // read_file();
    0
}


// ------------------------------ DELETE DATA ---------------------------------
#[no_mangle]
pub extern "C" fn delete_data() -> i32 {
    let mut data = [0_u8; 4096];

    let mut file = match SgxFile::open("wallet") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::open failed.");
            return 1;
        },
    };

    let read_size = match file.read(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::read failed.");
            return 2;
        },
    };

    let DeserializeData = DeSerializeHelper::<FileData>::new(data.to_vec());
    let mut file_data = match DeserializeData.decode() {
        Some(d) => d,
        None => {
            println!("[FAIL] Decode data failed.");
            return 3;
        },
    };

    drop(file);

    let mut key = String::new();

    println!("[-] Enter the key to delete:");
    std::io::stdin().read_line(&mut key).expect("[FAIL] Failed to read key");
    key = key.trim().to_string();

    if file_data.data.remove(&key).is_none() {
        println!("[FAIL] Username not found.");
        return 4;
    }

    let SerializeData = SerializeHelper::new();
    let updated_data = match SerializeData.encode(&file_data) {
        Some(d) => d,
        None => {
            println!("[FAIL] Encode data failed.");
            return 5;
        },
    };

    let mut file = match SgxFile::create("wallet") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::create failed.");
            return 6;
        },
    };

    let write_size = match file.write(&updated_data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::write failed.");
            return 7;
        },
    };

    println!("[-] Data deletion completed successfully!");
    drop(file);
    // read_file();
    0
}

// ------------------------- FIND BY KEY -------------------------------------
#[no_mangle]
pub extern "C" fn find_by_key() -> i32 {
    let mut data = [0_u8; 4096];

    let mut file = match SgxFile::open("wallet") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::open failed.");
            return 1;
        },
    };

    let read_size = match file.read(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::read failed.");
            return 2;
        },
    };

    let DeserializeData = DeSerializeHelper::<FileData>::new(data.to_vec());
    let file_data = match DeserializeData.decode() {
        Some(d) => d,
        None => {
            println!("[FAIL] Decode data failed.");
            return 3;
        },
    };

    drop(file);

    let mut key = String::new();

    println!("[+] Enter the username for password to find:");
    std::io::stdin().read_line(&mut key).expect("[FAIL] Failed to read key");
    key = key.trim().to_string();

    match file_data.data.get(&key) {
        Some(value) => {
            println!("[OK] Found password for username '{}'-> {}", key, value);
        }
        None => {
            println!("[Error] Username not found.");
            return 4;
        }
    }

    0
}


#[no_mangle]
// ------------------------- CLEAR FILE -------------------------------------
pub extern "C" fn delete_file() -> i32 { 
    let empty_content = "";

    let mut file = match SgxFile::create("wallet") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::create failed.");
            return 1;
        },
    };

    let write_size = match file.write(empty_content.as_bytes()) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::write failed.");
            return 2;
        },
    };

    println!("[OK] File content cleared successfully.");
    0
}

//------------------------------- CHANGE MASTER PASSWORD --------------------------------

// 
#[no_mangle]
pub extern "C" fn change_password() -> i32 {
    let mut data = [0_u8; 4096];

    // OPEN
    let mut file = match SgxFile::open("creds") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::open failed.");
            return 1;
        },
    };

    // READ SIZE
    let read_size = match file.read(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::read failed.");
            return 2;
        },
    };

    // DECODE
    let DeserializeData = DeSerializeHelper::<FileData>::new(data.to_vec());
    let mut file_data = match DeserializeData.decode() {
        Some(d) => d,
        None => {
            println!("[FAIL] Decode data failed.");
            return 3;
        },
    };

    drop(file);

    // Get the only key in the HashMap
    let key = file_data.data.keys().next().unwrap().clone();

    // Get the updated password
    let mut updated_password = String::new();
    let mut valid_password = false;
    while !valid_password {
        println!("[+] Enter the updated password (at least 8 characters, including symbols and numbers):");
        std::io::stdin().read_line(&mut updated_password).expect("[FAIL] Failed to read password");
        updated_password = updated_password.trim().to_string();

        // Check password policy
        let mut has_digit = false;
        let mut has_symbol = false;
        for c in updated_password.chars() {
            if c.is_digit(10) {
                has_digit = true;
            } else if c.is_ascii_punctuation() {
                has_symbol = true;
            }
        }
        if updated_password.len() >= 8 && has_digit && has_symbol {
            valid_password = true;
        } else {
            println!("[FAIL] Password must be at least 8 characters, including symbols and numbers. Please try again.");
        }
    }

    // XOR the password with a secret key
    let secret_key = String::from("my_secret_key");
    let mut encrypted_password = String::new();
    for (i, c) in updated_password.chars().enumerate() {
        let key_char = secret_key.chars().nth(i % secret_key.len()).unwrap();
        let encrypted_char = (c as u8) ^ (key_char as u8);
        encrypted_password.push(encrypted_char as char);
    }

    // Update the password for the given key
    file_data.data.insert(key, encrypted_password);

    // ENCODING
    let SerializeData = SerializeHelper::new();
    let updated_data = match SerializeData.encode(&file_data) {
        Some(d) => d,
        None => {
            println!("[FAIL] Encode data failed.");
            return 4;
        },
    };

    // WRITE
    let mut file = match SgxFile::create("creds") {
        Ok(f) => f,
        Err(_) => {
            println!("[FAIL] SgxFile::create failed.");
            return 5;
        },
    };

    let write_size = match file.write(&updated_data) {
        Ok(len) => len,
        Err(_) => {
            println!("[FAIL] SgxFile::write failed.");
            return 6;
        },
    };

    println!("[OK] Update password success");
    drop(file);
    0
}


//------------------------------ RECOMMEND PASSWORD -----------------------------
#[no_mangle]
pub fn recommend_password() -> i32 {
    let lowercase_chars: Vec<u8> = (b'a'..=b'z').collect();
    let uppercase_chars: Vec<u8> = (b'A'..=b'Z').collect();
    let numbers: Vec<u8> = (b'0'..=b'9').collect();
    let symbols: Vec<u8> = (b"!@#$%^&*()_+-=[]{}|;:,.<>?").to_vec();

    let char_vecs: [&Vec<u8>; 4] = [&lowercase_chars, &uppercase_chars, &numbers, &symbols];

    let mut password = String::new();

    for _ in 0..16 {
        let char_type = sgx_rand::random::<usize>() % 4;
        let char_vec = char_vecs[char_type];
        let char_index = sgx_rand::random::<usize>() % char_vec.len();
        let chosen_char = char_vec[char_index] as char;
        password.push(chosen_char);
    }

    println!("[NEW] Recommended password is -> {}",password);
    0
}

