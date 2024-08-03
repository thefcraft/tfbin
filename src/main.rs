use core::panic;
use std::ffi::OsStr;
use std::{fs, path};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::exit;


mod utils;
use crossterm::terminal;
use utils::basic_symmetric_key_encrpter::BasicSymmetricKeyEncrpter as BSKE;


// fn main() {
//     let pbstr = "\u{25A0}".repeat(20).to_string();
//     let pbwid = "-".repeat(20).to_string();
//     let mut perc;
//     let mut lpad;
//     for k in 1..4 {
//         for i in 1..21 {
//             perc = (i as f64) / 20.0;
//             lpad = (perc * 20.0).floor();
//             sleep(Duration::from_millis(100));
//             print!(
//                 "\r Processing data {} of 3: [{}{}]{}%",
//                 k,
//                 &pbstr[0..'\u{25A0}'.len_utf8()*(lpad.trunc() as usize)],
//                 &pbwid[0..((20.0 - lpad).trunc() as usize)],
//                 (perc * 100.0).trunc()
//             );
//             stdout().flush().unwrap();
//         }
//         print!("\n");
//     }
// }

fn save(path: &Path, depth: usize, f: &mut File, bske: Option<&BSKE>, protect_name: Option<bool>) -> std::io::Result<()>{
    let mut files = Vec::new();
    let mut dirs = Vec::new();

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_file() {
            files.push(entry_path);
        } else if entry_path.is_dir() {
            dirs.push(entry_path);
        }
    }
    let protect_name  = protect_name.unwrap_or_else(|| false);
    if depth == 0{
        if let Some(bske) = bske { // password protected flag with protect_name
            if protect_name{
                f.write(&[2]).unwrap(); 
            }else{
                f.write(&[1]).unwrap(); 
            }
            let key_hash_sha256_pow_10 = bske.key_hash_sha256_pow_10;
            f.write_all(&key_hash_sha256_pow_10).unwrap();
        }else{
            f.write(&[0]).unwrap(); 
        }
    }
    
    f.write(&files.len().to_ne_bytes()).unwrap(); // num_files
    let mut perc = 0.0;
    let mut lpad = 0.0;
    let n = files.len() + dirs.len() - 1;
    // Process files
    if depth == 0{
        let pbstr = "\u{25A0}".repeat(20).to_string();
        let pbwid = "-".repeat(20).to_string();
        for (i, file) in files.iter().enumerate() {
                perc = (i as f64) / (n as f64);
                lpad = (perc * 20.0).floor();
                
                print!(
                    "\r Processing: [{}{}]{}%",
                    &pbstr[0..'\u{25A0}'.len_utf8()*(lpad.trunc() as usize)],
                    &pbwid[0..((20.0 - lpad).trunc() as usize)],
                    (perc * 100.0).trunc()
                );
                io::stdout().flush().unwrap();
            let metadata = file.metadata().expect("metadata call failed");
            let file_size = metadata.len() as usize;
            
            let name = file.file_name().unwrap().as_encoded_bytes(); // OsStr::from_encoded_bytes_unchecked
            let name = if let Some(bske) = bske {
                if protect_name{
                    bske.encrypt(name)
                }else{
                    Vec::from(name)
                }
            }else{
                Vec::from(name)
            };
            f.write(&file_size.to_ne_bytes()).unwrap(); // file_size
            f.write(&name.len().to_ne_bytes()).unwrap(); // name_len
            f.write(&name).unwrap(); // name          
    
            let mut file = File::open(file).unwrap();
            let mut buffer = Vec::<u8>::with_capacity(file_size);
            file.read_to_end(&mut buffer).unwrap();
            let buffer = if let Some(bske) = bske {
                bske.encrypt(&buffer)
            }else{
                buffer
            };
            f.write_all(&buffer).unwrap(); // data
        }
    }else{
        for file in files {
            let metadata = file.metadata().expect("metadata call failed");
            let file_size = metadata.len() as usize;
            
            let name = file.file_name().unwrap().as_encoded_bytes(); // OsStr::from_encoded_bytes_unchecked
            let name = if let Some(bske) = bske {
                if protect_name{
                    bske.encrypt(name)
                }else{
                    Vec::from(name)
                }
            }else{
                Vec::from(name)
            };
            f.write(&file_size.to_ne_bytes()).unwrap(); // file_size
            f.write(&name.len().to_ne_bytes()).unwrap(); // name_len
            f.write(&name).unwrap(); // name          
    
            let mut file = File::open(file).unwrap();
            let mut buffer = Vec::<u8>::with_capacity(file_size);
            file.read_to_end(&mut buffer).unwrap();
            let buffer = if let Some(bske) = bske {
                bske.encrypt(&buffer)
            }else{
                buffer
            };
            f.write_all(&buffer).unwrap(); // data
        }
    }
    

    f.write(&dirs.len().to_ne_bytes()).unwrap(); // num_dirs
    if depth == 0{
        let pbstr = "\u{25A0}".repeat(20).to_string();
        let pbwid = "-".repeat(20).to_string();
        
        // Process directories
        for (i, dir) in dirs.iter().enumerate() {

            perc = (i as f64) / (n as f64);
            lpad = (perc * 20.0).floor();
            
            print!(
                "\r Processing: [{}{}]{}%",
                &pbstr[0..'\u{25A0}'.len_utf8()*(lpad.trunc() as usize)],
                &pbwid[0..((20.0 - lpad).trunc() as usize)],
                (perc * 100.0).trunc()
            );
            io::stdout().flush().unwrap();

            f.write(&depth.to_ne_bytes()).unwrap(); // depth
            let name = dir.file_name().unwrap().as_encoded_bytes(); // OsStr::from_encoded_bytes_unchecked
            let name = if let Some(bske) = bske {
                if protect_name{
                    bske.encrypt(name)
                }else{
                    Vec::from(name)
                }
            }else{
                Vec::from(name)
            };
            f.write(&name.len().to_ne_bytes()).unwrap(); // name_len
            f.write(&name).unwrap(); // name          

            save(&dir, depth+1, f, bske, Some(protect_name))?;
        }
    }else{
        // Process directories
        for dir in dirs {
            f.write(&depth.to_ne_bytes()).unwrap(); // depth
            let name = dir.file_name().unwrap().as_encoded_bytes(); // OsStr::from_encoded_bytes_unchecked
            let name = if let Some(bske) = bske {
                if protect_name{
                    bske.encrypt(name)
                }else{
                    Vec::from(name)
                }
            }else{
                Vec::from(name)
            };
            f.write(&name.len().to_ne_bytes()).unwrap(); // name_len
            f.write(&name).unwrap(); // name          

            save(&dir, depth+1, f, bske, Some(protect_name))?;
        }
    }
    

    Ok(())
}
fn load_(f: &mut File, offset:u64, out: &Path, bske: Option<&BSKE>, mut protect_name: Option<bool>) -> std::io::Result<u64>{
    assert!(offset == 0 && protect_name == None || offset > 0, "protected name should be None");
    fs::create_dir_all(out)?;
    // println!("{}", out.display());
    let mut buffer = [0; 8];
    
    let mut offset = offset;
    if offset == 0{
        let mut tmp = [0; 1];
        f.read(&mut tmp)?;
        let password_protected_flag = u8::from_ne_bytes(tmp); // password protected flag with protect_name
        
        offset += 1;
        let password_protected: bool;
        match password_protected_flag {
            0 => {
              protect_name = Some(false);
              password_protected = false;  
            },
            1 => {
                protect_name = Some(false);
                password_protected = true;
            },
            2 => {
                protect_name = Some(true);
                password_protected = true;
            },
            _ => panic!("some must be wrong might be wrong file")
        }
        if password_protected{
            assert!(bske.is_some(), "file is password_protected please provide password");
        }else {
            assert!(bske.is_none(), "file is not password protected but password is provided");
        }
        
        if password_protected{
            let mut key_hash_sha256_pow_10 = [0; 32];
            f.seek_read(&mut key_hash_sha256_pow_10, offset)?;    
            if let Some(bske) = bske {
                assert!(bske.key_hash_sha256_pow_10 == key_hash_sha256_pow_10, "password is incorrect please provide right password");
            }
            offset += 32;
        }
    }
    
    f.seek_read(&mut buffer, offset)?;
    let num_files = usize::from_ne_bytes(buffer);
    offset += 8;    
    
    let protect_name = protect_name.unwrap();

    for _ in 0..num_files{
        f.seek_read(&mut buffer, offset)?;
        let file_size = usize::from_ne_bytes(buffer); // file_size
        f.seek_read(&mut buffer, offset+8)?;
        let name_len = usize::from_ne_bytes(buffer); // name_len
        let mut bytes = vec![0; name_len];
        f.seek_read(&mut bytes, offset+16)?; // name
        offset += 16+name_len as u64;

        bytes = if protect_name{
            if let Some(bske) = bske {
                bske.decrypt(&bytes)
            }else {panic!()}
        }else{
            bytes
        };

        let name = unsafe {
                            OsStr::from_encoded_bytes_unchecked(&bytes)
                        };
    
        let mut file = File::create(&out.join(name)).unwrap();
        
        let mut data = vec![0; file_size]; // data
        f.seek_read(&mut data, offset)?;
        data = if let Some(bske) = bske {
                bske.decrypt(&data)
        }else{
            data
        };
        file.write_all(&data)?;
        
        offset += file_size as u64;

        // println!("{:?}", name);
    }
    
    f.seek_read(&mut buffer, offset)?;
    let num_dirs = usize::from_ne_bytes(buffer);
    
    for _ in 0..num_dirs{
        f.seek_read(&mut buffer, offset+8)?;
        let depth = usize::from_ne_bytes(buffer); // depth
        f.seek_read(&mut buffer, offset+16)?;
        let name_len = usize::from_ne_bytes(buffer); // name_len
        let mut bytes = vec![0; name_len];
        f.seek_read(&mut bytes, offset+24)?; // name
        offset += 24+name_len as u64;
        bytes = if protect_name{
            if let Some(bske) = bske {
                bske.decrypt(&bytes)
            }else {panic!()}
        }else{
            bytes
        };
        let name = unsafe {
            OsStr::from_encoded_bytes_unchecked(&bytes)
        };
        offset = load_(f, offset, &out.join(name), bske, Some(protect_name))?;
    }
    Ok(offset)
}
fn load(f: &mut File, out: &Path) -> std::io::Result<u64>{
    let mut tmp = [0; 1];
    f.read(&mut tmp)?;
    let password_protected_flag = u8::from_ne_bytes(tmp); // password protected flag with protect_name
        
    let password_protected: bool;
    let protect_name: bool;
    match password_protected_flag {
        0 => {
          protect_name = false;
          password_protected = false;  
        },
        1 => {
            protect_name = false;
            password_protected = true;
        },
        2 => {
            protect_name = true;
            password_protected = true;
        },
        _ => panic!("some must be wrong might be wrong file")
    }
    let mut key: Vec<u8> = Vec::<u8>::new();
    let mut key_hash_sha256_pow_10 = [0; 32];
    let offset = if password_protected{
        f.seek_read(&mut key_hash_sha256_pow_10, 1)?;    
        let mut password = String::new();
        print!("This file is protcted by password, enter your password: "); // termion = "1.5" for hiding terminal
        io::stdout().flush().unwrap(); // Ensure the prompt is displayed immediately
        io::stdin().read_line(&mut password).unwrap();
        let password = password.trim();
        println!("Your password is: `{}`", password);
        for c in password.bytes(){key.push(c);}
        33
    }else{
        1
    };

    if password_protected{
        let bske = BSKE::new(key);
        assert!(bske.key_hash_sha256_pow_10 == key_hash_sha256_pow_10, "password is incorrect please provide right password");
        load_(f, offset, out, Some(&bske), Some(protect_name))
    }else{
        load_(f, offset, out, None, None)
    }
}

struct TFFILE<'a>{
    f: &'a File,
    offset_data: u64,
    offset_next: u64,
    file_size: usize,
    name: String,
    // bske: &'a Option<&'a BSKE>
}
impl<'a> TFFILE<'a> {
    fn new(f: &'a File, offset: u64, protect_name: Option<bool>, bske: Option<&BSKE>)->Self{
        let protect_name = protect_name.unwrap_or_else(|| false);
        let mut buffer = [0; 8];
        f.seek_read(&mut buffer, offset).unwrap();
        let file_size = usize::from_ne_bytes(buffer); // file_size
        
        f.seek_read(&mut buffer, offset+8).unwrap();
        let name_len = usize::from_ne_bytes(buffer); // name_len

        let mut bytes = vec![0; name_len];
        f.seek_read(&mut bytes, offset+16).unwrap(); // name
        bytes = if protect_name{
            if let Some(bske) = bske {
                bske.decrypt(&bytes)
            }else {panic!()}
        }else{
            bytes
        };
        let name = unsafe {
                OsStr::from_encoded_bytes_unchecked(&bytes)
            };
        let name = String::from(name.to_str().unwrap());
        let offset_data = offset + 16 + name_len as u64;
        let offset_next = offset + 16 + name_len as u64 + file_size as u64;
        
        Self { f, offset_data, offset_next, file_size, name}
    }
    fn read(&self, bske: &Option<BSKE>)->Vec<u8>{
        let mut data = vec![0; self.file_size]; // data
        self.f.seek_read(&mut data, self.offset_data).unwrap();
        if let Some(bske) = bske {
            bske.decrypt(&data)
        }else{
            data
        }
    }
}

struct TFDIR<'a>{
    f: &'a File,
    offset_next: u64,
    len: usize,
    n_files: usize, 
    n_folders: usize, 
    name: String,
    dirs: Vec<TFDIR<'a>>,
    files: Vec<TFFILE<'a>>,
}
impl<'a> TFDIR<'a> {
    fn new(f: &'a File, mut offset: u64, name: &str, protect_name: Option<bool>, bske: Option<&BSKE>)->Self{
        let mut buffer = [0; 8];
        let protect_name = protect_name.unwrap_or_else(|| false);
        f.seek_read(&mut buffer, offset).unwrap();
        let num_files = usize::from_ne_bytes(buffer);
        offset += 8;
        let mut files = Vec::<TFFILE<'a>>::with_capacity(num_files);
        for _ in 0..num_files{
            let file = TFFILE::new(f, offset, Some(protect_name), bske);
            offset = file.offset_next;
            files.push(file);
        }
        
        f.seek_read(&mut buffer, offset).unwrap();
        let num_dirs = usize::from_ne_bytes(buffer);
        let mut dirs = Vec::<TFDIR<'a>>::with_capacity(num_files);
        offset += 8;
        let mut n_files: usize = num_files;
        let mut n_folders: usize = num_dirs;
        for _ in 0..num_dirs{
            f.seek_read(&mut buffer, offset).unwrap();
            let depth = usize::from_ne_bytes(buffer); // depth
            f.seek_read(&mut buffer, offset+8).unwrap();
            let name_len = usize::from_ne_bytes(buffer); // name_len
            let mut bytes = vec![0; name_len];
            f.seek_read(&mut bytes, offset+16).unwrap(); // name
            offset += 16+name_len as u64;
            bytes = if protect_name{
                if let Some(bske) = bske {
                    bske.decrypt(&bytes)
                }else {panic!()}
            }else{
                bytes
            };
            let name = unsafe {
                OsStr::from_encoded_bytes_unchecked(&bytes)
            };
            let name = name.to_str().unwrap();
            let dir = TFDIR::new(f, offset, &name, Some(protect_name), bske);
            n_files += dir.n_files;
            n_folders += dir.n_folders;
            offset = dir.offset_next;
            dirs.push(dir);
        }
        
        let offset_next = offset;

        Self { f, offset_next, len: num_dirs+num_files, n_files, n_folders, name: name.to_string(), dirs, files }
    }
}

struct TFBIN<'a>{
    root: TFDIR<'a>,
    path: Vec<usize>,
    depth: usize,
    bske: Option<BSKE>,
}

enum file_folder<'a> {
    folder(&'a TFDIR<'a>),
    file(&'a TFFILE<'a>),
}
impl<'a> TFBIN<'a> {
    fn new(mut f: &'a File) -> Self {
        let mut tmp = [0; 1];
        f.read(&mut tmp).unwrap();
        let password_protected_flag = u8::from_ne_bytes(tmp); // password protected flag with protect_name
        let password_protected: bool;
        let protect_name: bool;
        match password_protected_flag {
            0 => {
              protect_name = false;
              password_protected = false;  
            },
            1 => {
                protect_name = false;
                password_protected = true;
            },
            2 => {
                protect_name = true;
                password_protected = true;
            },
            _ => panic!("some must be wrong might be wrong file")
        }
        let mut key: Vec<u8> = Vec::<u8>::new();
        let mut key_hash_sha256_pow_10 = [0; 32];
        let offset = if password_protected{
            f.seek_read(&mut key_hash_sha256_pow_10, 1).unwrap();    
            let mut password = String::new();
            disable_raw_mode().unwrap();
            print!("This file is protcted by password, enter your password: "); // termion = "1.5" for hiding terminal
            io::stdout().flush().unwrap(); // Ensure the prompt is displayed immediately
            io::stdin().read_line(&mut password).unwrap();
            let password = password.trim();
            println!("Your password is: `{}`", password);
            enable_raw_mode().unwrap();
            for c in password.bytes(){key.push(c);}
            33
        }else{
            1
        };
        
        let (root, bske) = if password_protected{
            let bske = BSKE::new(key);
            assert!(bske.key_hash_sha256_pow_10 == key_hash_sha256_pow_10, "password is incorrect please provide right password");
            (TFDIR::new(f, offset, &"root", Some(protect_name), Some(&bske)), Some(bske))
        }else{
            (TFDIR::new(f, offset, &"root", Some(protect_name), None), None)
        };

        // let root = TFDIR::new(f, offset, &"root", Some(protect_name), Some(())&bske);
        let path = vec![];
        return Self{
            root,
            path,
            depth: 0,
            bske,
        };
    }
    fn get(&self)->file_folder{
        let mut root = &self.root;
        
        for &i in self.path.iter(){
            if i < root.dirs.len(){
                root = &root.dirs[i];
            }else{
                return file_folder::file(&root.files[i - root.dirs.len()]);
            }
        }
        return file_folder::folder(&root);
    }
    fn get_location(&self)->String{
        let mut root = &self.root;
        let mut result = Vec::<String>::with_capacity(self.path.len()+1);
        for &i in self.path.iter(){
            if i < root.dirs.len(){
                result.push(root.name.clone());
                root = &root.dirs[i];
            }else{
                let file = &root.files[i - root.dirs.len()];
                result.push(file.name.clone());
            }
        }
        result.push(root.name.clone());
        result.join("/")
    }
    fn is_file(&self) -> bool{
        let mut root = &self.root;
        for  &i in self.path.iter(){
            if i < root.dirs.len(){
                root = &root.dirs[i];
            }else{
                return true;
            }
        }
        return false;
    }
    
}

use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState},
    Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use native_dialog::FileDialog;


// use tempfile::NamedTempFile;
use std::env;
use std::process::{Command, Stdio};

struct App_pre{
    state: ListState,
    items: Vec<String>,
    quit: bool,
}

impl App_pre {
    fn new() -> Self {
        App_pre {
            state: ListState::default(),
            items: Vec::new(),
            quit: false,
        }
    }

    fn update_items(&mut self) {
        self.items.clear();
        self.items.push(String::from("press q to quit"));        
        self.items.push(String::from("convert folder into tfbin format"));    
        self.items.push(String::from("convert tfbin back into folder"));    
        self.items.push(String::from("open tfbin file"));
        self.state.select(Some(0));
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn enter(&mut self) {
        self.quit = true;
    }
}

struct App<'a> {
    state: ListState,
    items: Vec<String>,
    root: TFBIN<'a>,
}

impl<'a> App<'a> {
    fn new(f: &'a File) -> Self {
        let root = TFBIN::new(f);
        App {
            state: ListState::default(),
            items: Vec::new(),
            root,
        }
    }

    fn update_items(&mut self) {
        self.items.clear();
        // self.items.push(format!("{:?}", self.root.path));
        self.items.push(String::from(".."));        
        
        let r = self.root.get();
        if let file_folder::folder(r) = r{
            for f in r.dirs.iter() {
                self.items.push(f.name.clone());
            }
            for f in r.files.iter() {
                self.items.push(f.name.clone());
            }
        }else {
            panic!();
        }
        
        self.state.select(Some(0));
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn enter(&mut self) {
        if let Some(selected) = self.state.selected() {
            let item = &self.items[selected];
            
            if item == ".." {
                if self.root.path.len() >= 1{
                    self.root.path.pop();
                }
            } else {
                self.root.path.push(selected - 1); // 1 if idx is not printing
                if self.root.is_file(){
                    if let file_folder::file(file) = self.root.get(){
                        let raw_bytes = file.read(&self.root.bske);

                        // let mut temp_file = NamedTempFile::new().unwrap();
                        // temp_file.write_all(&raw_bytes).unwrap();
                        // let temp_file_path = temp_file.path().to_str().expect("Invalid path");

                        match env::current_exe() {
                            Ok(path) => {
                                let mut temp_file_path = path.clone();
                                temp_file_path.set_extension("temp.tmp");
                                let a = file.name.split(".").last().unwrap_or_else(|| &"tmp");
                                // temp_file_path.set_extension(file.name.as_str());
                                temp_file_path.set_extension(a);

                                let mut file = File::create(&temp_file_path).unwrap();
                                file.write_all(&raw_bytes).unwrap();
                                drop(file);

                                // Command::new(r"C:\Program Files\VideoLAN\VLC\vlc.exe")
                                //     .arg(&temp_file_path)
                                //     .spawn()
                                //     .expect("Failed to start VLC");

                                // Prepare the command to open the file
                                // let file_path_str: &str = &temp_file_path.to_str().unwrap();
                                let mut command = Command::new("cmd");
                                command.args(&["/C", "start", "/WAIT"])
                                        .arg(&temp_file_path)
                                       .stdout(Stdio::null())
                                       .stderr(Stdio::null());
                                
                                // Spawn the process
                                let mut child = match command.spawn() {
                                    Ok(child) => child,
                                    Err(e) => {
                                        eprintln!("Failed to start process: {}", e);
                                        return;
                                    }
                                };

                                // Start program with the temporary file
                                // let mut child = match Command::new("cmd")
                                //     .args(&["/C", "start", "", &temp_file_path.to_str().unwrap()])
                                //     // .arg(&temp_file_path)
                                //     .spawn() {
                                //         Ok(child) => child,
                                //         Err(e) => {
                                //             eprintln!("Failed to start: {}", e);
                                //             return;
                                //         }
                                //     };
                                // Wait for programm to finish
                                if let Err(e) = child.wait() {
                                    eprintln!("Failed to wait on process: {}", e);
                                    return;
                                }
                                // Delete the temporary file
                                if let Err(e) = fs::remove_file(&temp_file_path) {
                                    eprintln!("Failed to delete the file: {}", e);
                                }
                            },
                            Err(e) => panic!("Error getting the executable path: {}", e),
                        }
                    }
                    self.root.path.pop();
                }
            }
            self.update_items();
        }
    }
}

fn safe_panic(mut terminal: Terminal<CrosstermBackend<std::io::Stdout>>, string: &str) -> !{
    disable_raw_mode().unwrap();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    ).unwrap();
    terminal.show_cursor().unwrap();
    panic!("{}", string)
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1{
        let in_tfbin_file_path = &args[1];
        print!("{:?}", args);
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal: Terminal<CrosstermBackend<std::io::Stdout>> = Terminal::new(backend)?;
    
        let file = File::open(in_tfbin_file_path).unwrap();
        
        let mut app = App::new(&file);
        app.update_items();
    
        terminal.clear().unwrap();
    
        loop {
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(1)
                    .constraints([Constraint::Percentage(100)].as_ref())
                    .split(f.size());
    
                let items: Vec<ListItem> = app
                    .items
                    .iter()
                    .map(|i| {
                        let lines = vec![Spans::from(i.clone())];
                        ListItem::new(lines).style(Style::default().fg(Color::White))
                    })
                    .collect();
                
                // app.root.path
    
                let items = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title(format!("File Explorer PATH: {}", app.root.get_location().as_str())))
                    .highlight_style(
                        Style::default()
                            .bg(Color::Yellow)
                            .fg(Color::Black)
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol("> ");
    
                f.render_stateful_widget(items, chunks[0], &mut app.state);
            })?;
    
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Down => app.next(),
                    KeyCode::Up => app.previous(),
                    KeyCode::Enter => app.enter(),
                    _ => {}
                }
            }
        }
    
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
    
        return Ok(());
    }
    // let mut password = String::new();
    // print!("Please enter your password: "); // termion = "1.5" for hiding terminal
    // io::stdout().flush().unwrap(); // Ensure the prompt is displayed immediately
    // io::stdin().read_line(&mut password).unwrap();
    // let password = password.trim();
    // println!("Your password is: `{}`", password);
    // let mut bytes: Vec<u8> = Vec::<u8>::new();
    // for c in password.bytes(){bytes.push(c);}

    // let mut file = File::create(r"C:\ThefCraft\thefcraft-rust\tfbin\src\main.bin").unwrap();
    // let bske = BSKE::new(bytes); // BSKE::from_random_key(32);
    // println!("{:?}", bske.key_hash_sha256_pow_10); // [208, 65, 40, 241, 14, 80, 78, 141, 155, 122, 114, 74, 216, 199, 121, 193, 145, 247, 235, 128, 160, 184, 204, 150, 177, 213, 176, 246, 239, 17, 109, 125]
    // save(Path::new(r"C:\ThefCraft\leetcode"), 0, &mut file, Some(&bske), Some(true)).unwrap();

    // let mut file = File::open(r"C:\ThefCraft\thefcraft-rust\tfbin\src\main.bin").unwrap();
    // load(&mut file, Path::new(r".\src\main_out")).unwrap();

    

    // let bske = BSKE::new();
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal: Terminal<CrosstermBackend<std::io::Stdout>> = Terminal::new(backend)?;
    
    // let mut file = File::create(r"C:\ThefCraft\thefcraft-rust\tfbin\src\main.bin").unwrap();
    // save(Path::new(r"C:\ThefCraft\thefcraft-rust\tfbin\src\test"), 0, &mut file).unwrap();
    
    let mut quit_pre = false;
    let mut app = App_pre::new();
    
    app.update_items();
    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Percentage(100)].as_ref())
                .split(f.size());

            let items: Vec<ListItem> = app
                .items
                .iter()
                .map(|i| {
                    let lines = vec![Spans::from(i.clone())];
                    ListItem::new(lines).style(Style::default().fg(Color::White))
                })
                .collect();

            let items = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("TFBIN"))
                .highlight_style(
                    Style::default()
                        .bg(Color::Yellow)
                        .fg(Color::Black)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("> ");

            f.render_stateful_widget(items, chunks[0], &mut app.state);
        })?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') =>{
                    quit_pre = true;
                    app.state.select(Some(0));
                    break;
                }
                KeyCode::Down => app.next(),
                KeyCode::Up => app.previous(),
                KeyCode::Enter => app.enter(),
                _ => {}
            }
        }
        if app.quit {
            quit_pre = true;
            break;
        }
    }

    let in_tfbin_file_path;
    if quit_pre{
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        
        if let Some(selected) = app.state.selected() {
            
            match selected {
                0 => {
                    return Ok(());
                },
                1 => {
                    let in_folder_path: PathBuf;
                    match FileDialog::new().show_open_single_dir() {
                        Ok(folder_path) => {
                            // Convert the folder path to a string
                            if let Some(path) = folder_path {
                                println!("Selected folder path: {}", path.display());
                                in_folder_path = path;
                            } else {
                                safe_panic(terminal, "Invalid folder path.");
                            }
                        }
                        Err(e) => {
                            safe_panic(terminal, format!("Failed to open folder dialog: {}", e).as_str());
                        }
                    }
                    
                    let out_file_path: PathBuf;
                    match FileDialog::new().set_location(&in_folder_path.parent().unwrap())
                    .set_filename(format!("{}.tfbin", in_folder_path.file_name().unwrap().to_str().unwrap()).as_str()).show_save_single_file() {
                        Ok(folder_path) => {
                            // Convert the folder path to a string
                            if let Some(path) = folder_path {
                                println!("Selected file path: {}", path.display());
                                out_file_path = path;
                            } else {
                                safe_panic(terminal, "Invalid file path.");
                            }
                        }
                        Err(e) => {
                            safe_panic(terminal, format!("Failed to open file dialog: {}", e).as_str());
                        }
                    }
                    let mut file = File::create(out_file_path).unwrap();
                    
                    let mut password_flag = String::new();
                    
                    input_password(terminal); // don't know but this is working ...


                    print!("Please enter Y to add password: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut password_flag).unwrap();
                    let password_flag = password_flag.trim();
                    if password_flag == "Y"{
                        let mut password_flag = String::new();
                        print!("Please enter Y to hide file name: ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut password_flag).unwrap();
                        let password_flag = password_flag.trim();
                        
                        let mut password = String::new();
                        print!("Please enter your password: "); // termion = "1.5" for hiding terminal
                        io::stdout().flush().unwrap(); // Ensure the prompt is displayed immediately
                        io::stdin().read_line(&mut password).unwrap();
                        let password = password.trim();
                        println!("Your password is: `{}`", password);
                        let mut key: Vec<u8> = Vec::<u8>::new();
                        for c in password.bytes(){key.push(c);}
                        let bske = BSKE::new(key);
                        if password_flag == "Y"{
                            save(&in_folder_path, 0, &mut file, Some(&bske), Some(true)).unwrap();
                        }else{
                            save(&in_folder_path, 0, &mut file, Some(&bske), Some(false)).unwrap();
                        }
                    }else{
                        save(&in_folder_path, 0, &mut file, None, None).unwrap();
                    }

                    return Ok(());
                }
                2 => {
                    let in_file_path: PathBuf;
                    match FileDialog::new().show_open_single_file() {
                        Ok(file_path) => {
                            // Convert the folder path to a string
                            if let Some(path) = file_path {
                                println!("Selected file path: {}", path.display());
                                in_file_path = path;
                            } else {
                                safe_panic(terminal, "Invalid file path.");
                            }
                        }
                        Err(e) => {
                            safe_panic(terminal, format!("Failed to open file dialog: {}", e).as_str());
                        }
                    }
                    let mut file = File::open(&in_file_path).unwrap();
                    let out = &in_file_path.parent().unwrap().join(format!("dir-{}", in_file_path.file_name().unwrap().to_str().unwrap()));
                    println!("saved at : {}", out.display());
                    input_password(terminal);
                    load(&mut file, &out).unwrap();
                    return Ok(());
                }
                3 => {
                    match FileDialog::new().show_open_single_file() {
                        Ok(file_path) => {
                            // Convert the folder path to a string
                            if let Some(path) = file_path {
                                println!("Selected file path: {}", path.display());
                                in_tfbin_file_path = path;
                            } else {
                                safe_panic(terminal, "Invalid file path.");
                            }
                        }
                        Err(e) => {
                            safe_panic(terminal, format!("Failed to open file dialog: {}", e).as_str());
                        }
                    }
                }
                _ => {
                    safe_panic(terminal, "something went wrong");
                }
            }
        }else {
            safe_panic(terminal, "something went wrong");
        }
    }else {
        safe_panic(terminal, "something went wrong");
    }
    

    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal: Terminal<CrosstermBackend<std::io::Stdout>> = Terminal::new(backend)?;

    let file = File::open(in_tfbin_file_path).unwrap();
    
    let mut app = App::new(&file);
    app.update_items();

    terminal.clear().unwrap();

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Percentage(100)].as_ref())
                .split(f.size());

            let items: Vec<ListItem> = app
                .items
                .iter()
                .map(|i| {
                    let lines = vec![Spans::from(i.clone())];
                    ListItem::new(lines).style(Style::default().fg(Color::White))
                })
                .collect();
            
            // app.root.path

            let items = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(format!("File Explorer PATH: {}", app.root.get_location().as_str())))
                .highlight_style(
                    Style::default()
                        .bg(Color::Yellow)
                        .fg(Color::Black)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("> ");

            f.render_stateful_widget(items, chunks[0], &mut app.state);
        })?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Down => app.next(),
                KeyCode::Up => app.previous(),
                KeyCode::Enter => app.enter(),
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

use crossterm::{
    event::{KeyEvent, KeyModifiers},
};

fn input_password(terminal: Terminal<CrosstermBackend<std::io::Stdout>>){
    // Set terminal to raw mode
    enable_raw_mode().unwrap();
    // ...
    disable_raw_mode().unwrap();
}