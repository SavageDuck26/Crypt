use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::SystemTime;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key,
};
use argon2::{Argon2, Algorithm, Version, Params};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tar;
use termios::{Termios, ECHO, ICANON, TCSANOW};
use zeroize::{Zeroize, Zeroizing};
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

const CHUNK_SIZE: usize = 16 * 1024 * 1024; // 16 MB
const SALT_SIZE: usize = 32; // 256-bit Argon2id salt
const NONCE_SIZE: usize = 12; // 96-bit AES-GCM nonce

const ARGON2_MEM_COST: u32 = 262144; // 256 MB Argon2id memory cost
const ARGON2_TIME_COST: u32 = 12;     // Argon2id iterations

const ZSTD_COMPRESSION_LEVEL: i32 = 15;

const CRYPT_MAGIC: &[u8; 4] = b"CRPT";
const CRYPT_VERSION: u16 = 1;

// Default worker threads (used if CryptConfig.json is missing).
const DEFAULT_NUM_WORKERS: usize = 1;

// JSON config read from CryptConfig.json alongside the binary.
#[derive(Serialize, Deserialize)]
struct Config {
    num_workers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            num_workers: DEFAULT_NUM_WORKERS,
        }
    }
}

// Load CryptConfig.json from the executable's directory.
// Creates a default config if one doesn't exist.
fn load_config() -> Config {
    let config_path = {
        let exe = env::current_exe().expect("Failed to get executable path");
        let dir = exe.parent().expect("Failed to get executable directory");
        dir.join("CryptConfig.json")
    };

    if !config_path.exists() {
        let config = Config::default();
        let json = serde_json::to_string_pretty(&config)
            .expect("Failed to serialize default config");
        fs::write(&config_path, json).expect("Failed to write default config");
        println!("Created default config: {}", config_path.display());
        return config;
    }

    let json = fs::read_to_string(&config_path)
        .expect("Failed to read config file");
    serde_json::from_str(&json)
        .unwrap_or_else(|e| {
            eprintln!("[WARN] Failed to parse config '{}', using defaults: {}", config_path.display(), e);
            Config::default()
        })
}

// Print a progress bar like `|==========>.....| 67%` using carriage return. 6-7 Lmao
fn print_progress_bar(current: u64, total: u64, finished: bool) {
    if total == 0 { return; }
    let percent = (current as f64 / total as f64) * 100.0;
    let percent = percent.clamp(0.0, 100.0);
    let bar_width: usize = 50;
    let filled = ((percent / 100.0) * (bar_width as f64)).round() as usize;
    let filled = filled.min(bar_width);

    if finished {
        print!("\r|");
        for _ in 0..bar_width { print!("="); }
        println!("| {:.0}%", percent);
    } else {
        print!("\r|");
        for i in 0..bar_width {
            if i < filled {
                print!("=");
            } else if i == filled && filled < bar_width {
                print!(">");
            } else {
                print!(".");
            }
        }
        print!("| {:.0}%", percent);
    }
    std::io::stdout().flush().ok();
}

// Replace characters illegal in exFAT/Win32 filenames with underscores.
fn sanitize_path_component(component: &str) -> String {
    component.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\0' => '_',
            c if (c as u32) < 0x20 && c != '\t' => '_',
            '\\' => '/',
            c => c,
        })
        .collect()
}

// Extract a tar archive, sanitizing each path to be exFAT-safe.
fn unpack_tar_sanitized<R: Read>(archive: &mut tar::Archive<R>, base_path: &Path) -> std::io::Result<()> {
    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_path = entry.path()?.to_string_lossy().to_string();

        let sanitized: Vec<String> = entry_path.split('/')
            .map(sanitize_path_component)
            .collect();
        let sanitized_path = sanitized.join("/");

        if sanitized.iter().any(|c| c == ".." || c == ".") {
            eprintln!("[WARN] Skipping entry with path traversal: '{}'", sanitized_path);
            continue;
        }

        let full_path = base_path.join(&sanitized_path);

        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&full_path)?;
        } else {
            entry.unpack(&full_path)?;
        }
    }
    Ok(())
}

fn sanitize_filename(name: &str) -> String {
    if name.is_empty() { return "decrypted_output".to_string(); }
    if name.contains("..") || name.contains('/') || name.contains('\\') || name.contains('\0') {
        eprintln!("[WARN] Filename '{}' contains unsafe characters. Using fallback name.", name);
        return "decrypted_output".to_string();
    }
    if name == "." || name == ".." {
        eprintln!("[WARN] Filename '{}' is a special directory entry. Using fallback name.", name);
        return "decrypted_output".to_string();
    }
    name.to_string()
}

// Read a password with masked echo (`*` per keystroke).
fn get_password() -> Zeroizing<String> {
    println!("Enter password.");

    let stdin_fd = std::io::stdin().as_raw_fd();
    let orig_termios = Termios::from_fd(stdin_fd).expect("Failed to get terminal attributes");

    // Disable canonical mode (ICANON) for immediate keystroke reads and echo (ECHO) so
    // characters don't appear on screen.
    let mut raw = orig_termios.clone();
    raw.c_lflag &= !(ICANON | ECHO);
    raw.c_cc[termios::VMIN] = 1;
    raw.c_cc[termios::VTIME] = 0;
    termios::tcsetattr(stdin_fd, TCSANOW, &raw).expect("Failed to set raw terminal mode");

    // Restore terminal on exit (including panic unwind).
    struct RestoreTermios {
        fd: i32,
        orig: Termios,
    }
    impl Drop for RestoreTermios {
        fn drop(&mut self) {
            let _ = termios::tcsetattr(self.fd, TCSANOW, &self.orig);
        }
    }
    let _restore = RestoreTermios { fd: stdin_fd, orig: orig_termios };

    let mut password = String::new();
    let mut stdin = std::io::stdin();

    loop {
        let mut byte = [0u8; 1];
        match stdin.read_exact(&mut byte) {
            Ok(()) => {}
            Err(_) => break,
        }

        match byte[0] {
            b'\n' | b'\r' => {
                println!();
                break;
            }
            0x7f | 0x08 => {
                if password.pop().is_some() {
                    print!("\x08 \x08");
                    std::io::stdout().flush().ok();
                }
            }
            0x15 => {
                let len = password.len();
                password.clear();
                for _ in 0..len {
                    print!("\x08 \x08");
                }
                std::io::stdout().flush().ok();
            }
            0x03 => {
                println!("^C");
                std::process::exit(130);
            }
            0x04 => {
                println!();
                break;
            }
            0x20..=0x7E => {
                password.push(byte[0] as char);
                print!("*");
                std::io::stdout().flush().ok();
            }
            _ => {}
        }
    }

    Zeroizing::new(password)
}

fn get_input_paths() -> Vec<PathBuf> {
    println!("Enter paths (One per line, blank line to finish):");
    let mut all_input = String::new();
    loop {
        let mut line = String::new();
        let bytes_read = std::io::stdin().read_line(&mut line)
            .expect("Failed to read path input from stdin");
        if bytes_read == 0 { break; }
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            if all_input.is_empty() { continue; }
            break;
        }
        all_input.push_str(&trimmed);
        all_input.push('\n');
    }
    let mut paths = Vec::new();
    for line in all_input.lines() {
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() { continue; }
        let path = PathBuf::from(&trimmed);
        if path.exists() { paths.push(path); println!("Added: {}", trimmed); }
        else { println!("Path does not exist: {}. Skipping.", trimmed); }
    }
    if paths.is_empty() { println!("No valid paths entered."); }
    paths
}

fn get_choice() -> char {
    loop {
        println!("Enter 'e' to encrypt or 'd' to decrypt.");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Failed to read choice from stdin");
        let trimmed = input.trim();
        if trimmed == "e" { return 'e'; }
        if trimmed == "d" { return 'd'; }
        if trimmed.is_empty() { continue; }
        println!("Invalid choice, please enter 'e' or 'd'.");
    }
}

fn get_output_dir() -> Option<PathBuf> {
    println!("Enter output directory (or press Enter to use the source file's directory):");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Failed to read output directory from stdin");
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() { return None; }
    let path = PathBuf::from(&trimmed);
    if path.is_dir() {
        println!("Output directory: {}", path.display());
        Some(path)
    } else {
        println!("Path '{}' is not a valid directory. Using default (source file's directory).", trimmed);
        None
    }
}

fn make_salt() -> Zeroizing<[u8; SALT_SIZE]> {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    Zeroizing::new(salt)
}

fn build_argon2() -> Argon2<'static> {
    let lanes = num_cpus::get().max(1) as u32;
    let params = Params::new(ARGON2_MEM_COST, ARGON2_TIME_COST, lanes, None)
        .expect("invalid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn derive_key(password: &str, salt: &[u8; SALT_SIZE]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    build_argon2()
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .expect("key derivation failed");
    key
}

fn aes_encrypt(data: &[u8], key: &[u8]) -> std::io::Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("AES-GCM encryption failed: {}", e))
    })?;
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn aes_decrypt(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, aes_gcm::aead::Error> {
    if encrypted.len() < NONCE_SIZE { return Err(aes_gcm::aead::Error); }
    let nonce = &encrypted[..NONCE_SIZE];
    let ciphertext = &encrypted[NONCE_SIZE..];
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
}

/// Hash the current timestamp and return the first 8 hex characters.
/// This produces a unique suffix so repeated backups don't collide.
fn date_hash() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    nanos.hash(&mut hasher);
    format!("{:08x}", hasher.finish())
}

fn dir_total_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    if path.is_dir() {
        for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() { total += entry.metadata()?.len(); }
        }
    }
    Ok(total)
}

fn walkdir_and_add_to_tar<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    archive_name: &Path,
    source_dir: &Path,
) -> std::io::Result<()> {
    let mut skipped = 0u64;
    for entry in walkdir::WalkDir::new(source_dir).into_iter().filter_map(|e| e.ok()) {
        let ft = match entry.path().metadata() {
            Ok(m) => m,
            Err(_) => { skipped += 1; continue; }
        };
        if ft.is_dir() { continue; }
        if !ft.is_file() { skipped += 1; continue; }
        let relative = entry.path().strip_prefix(source_dir).unwrap_or(entry.path());
        let archive_entry = archive_name.join(relative);

        // Stream the file via BufReader instead of loading it entirely into RAM
        // (a 500 MB file would otherwise allocate that much memory).
        let file = match File::open(entry.path()) {
            Ok(f) => f,
            Err(e) => { eprintln!("[WARN] Skipping unreadable file '{}': {}", entry.path().display(), e); skipped += 1; continue; }
        };
        let file_size = file.metadata()?.len();
        let mut header = tar::Header::new_gnu();
        header.set_size(file_size);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mtime(0);
        header.set_mode(0o644);
        tar_builder.append_data(&mut header, &archive_entry, BufReader::new(file))?;
    }
    if skipped > 0 { eprintln!("[WARN] Skipped {} unreadable entries during tar creation", skipped); }
    Ok(())
}

fn stream_files_to_tar<W: Write + Send + 'static>(
    paths: Vec<PathBuf>,
    _archive_name: &str,
    writer: W,
) -> std::io::Result<()> {
    let mut tar_builder = tar::Builder::new(writer);
    for path in &paths {
        if path.is_dir() {
            let dir_name = path.file_name().unwrap_or_default();
            walkdir_and_add_to_tar(&mut tar_builder, Path::new(dir_name), path)?;
        } else if path.is_file() {
            let name = path.file_name().unwrap_or_default();
            let file = match File::open(path) {
                Ok(f) => f,
                Err(e) => { eprintln!("[WARN] Skipping unreadable file '{}': {}", path.display(), e); continue; }
            };
            let file_size = file.metadata()?.len();
            let mut header = tar::Header::new_gnu();
            header.set_size(file_size);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mtime(0);
            header.set_mode(0o644);
            tar_builder.append_data(&mut header, name, BufReader::new(file))?;
        } else {
            eprintln!("[WARN] Skipping path '{}': not a file or directory.", path.display());
        }
    }
    tar_builder.into_inner()?;
    Ok(())
}

fn compress_frame(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut compressed = Vec::new();
    {
        let mut encoder = ZstdEncoder::new(&mut compressed, ZSTD_COMPRESSION_LEVEL)?;
        encoder.write_all(data)?;
        encoder.finish()?;
    }
    Ok(compressed)
}

fn decompress_frame(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let decoder = ZstdDecoder::new(Cursor::new(data))?;
    let mut decompressed = Vec::new();
    std::io::copy(&mut BufReader::new(decoder), &mut decompressed)?;
    Ok(decompressed)
}

fn write_crypt_header(
    output_file: &mut BufWriter<File>,
    key: &[u8],
    salt: &[u8],
    is_directory: bool,
    archive_name: &str,
) -> std::io::Result<()> {
    output_file.write_all(CRYPT_MAGIC)?;
    output_file.write_all(&CRYPT_VERSION.to_le_bytes())?;
    output_file.write_all(salt)?;

    let type_byte: u8 = if is_directory { b'D' } else { b'F' };
    let name_bytes = archive_name.as_bytes();
    let name_len = name_bytes.len();
    if name_len > 65535 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Filename too long (max 65535 bytes)"));
    }

    let mut header_plaintext = Vec::with_capacity(1 + 2 + name_len);
    header_plaintext.push(type_byte);
    header_plaintext.extend_from_slice(&(name_len as u16).to_le_bytes());
    header_plaintext.extend_from_slice(name_bytes);

    let encrypted_header = aes_encrypt(&header_plaintext, key)?;
    let header_total_len = encrypted_header.len() as u16;
    output_file.write_all(&header_total_len.to_le_bytes())?;
    output_file.write_all(&encrypted_header)?;
    Ok(())
}

struct RawChunk {
    index: u64,
    data: Zeroizing<Vec<u8>>,
}

struct FinishedChunk {
    index: u64,
    compressed_len: u32,
    encrypted: Vec<u8>,
}

struct EncryptedChunk {
    index: u64,
    data: Vec<u8>,
}

struct DecryptedChunk {
    index: u64,
    data: Vec<u8>,
}

fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_BACKTRACE", "full");

    let config = load_config();
    let num_workers = config.num_workers.max(1);

    let num_cores = num_cpus::get();
    println!("Detected {} CPU cores. Using {} worker(s) (config).", num_cores, num_workers);

    let mut password = get_password();
    let decrypt_password: Zeroizing<String> = Zeroizing::new(password.to_string());

    use std::sync::mpsc;
    let (key_tx, key_rx) = mpsc::channel();
    let pw_for_thread = password.clone();
    password.zeroize();
    let handle_derive = thread::spawn(move || {
        let salt = make_salt();
        let key = derive_key(&pw_for_thread, &salt);
        let result: (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) = (salt, key);
        let _ = key_tx.send(result);
    });

    let input_paths = get_input_paths();

    if input_paths.is_empty() {
        handle_derive.join().unwrap();
        return Ok(());
    }

    let output_dir = get_output_dir();
    let choice = get_choice();

    match choice {
        'e' => {
            let (salt, key) = key_rx.recv().unwrap();
            handle_derive.join().unwrap();

            let (archive_name, is_directory) = if input_paths.len() == 1 {
                let name = input_paths[0].file_name().unwrap_or_default().to_string_lossy().to_string();
                (name, input_paths[0].is_dir())
            } else {
                let name = input_paths[0].file_name().unwrap_or_default().to_string_lossy().to_string();
                (name, true)
            };

            let stem = input_paths[0].file_stem().unwrap_or_default().to_string_lossy();
            let base_dir = output_dir.as_deref().unwrap_or(
                input_paths[0].parent().unwrap_or(Path::new("."))
            );
            let output_path = base_dir.join(format!("{}-{}.crypt", stem, date_hash()));

            let mut total_input_size = 0u64;
            for path in &input_paths {
                if path.is_dir() { total_input_size += dir_total_size(path)?; }
                else if path.is_file() { total_input_size += fs::metadata(path)?.len(); }
            }
            println!("  Total input size: ~{} MB", total_input_size / (1024 * 1024));

            // Pipeline: Tar thread (I/O) -> Pipe reader (I/O) -> crossbeam (CPU workers) -> Writer (I/O)
            // crossbeam_channel supports multiple consumers so workers pull in parallel.

            let (pipe_reader, pipe_writer) = os_pipe::pipe()?;

            let paths_clone = input_paths.clone();
            let name_clone = archive_name.clone();
            let tar_handle = thread::spawn(move || {
                stream_files_to_tar(paths_clone, &name_clone, pipe_writer)
            });

            // Bounded to num_workers so the pipe reader blocks when workers are busy,
            // creating natural backpressure that prevents memory from piling up.
            let (raw_tx, raw_rx) = crossbeam_channel::bounded::<RawChunk>(num_workers);
            let (finished_tx, finished_rx) = crossbeam_channel::bounded::<FinishedChunk>(num_workers * 2);

            let key_for_workers = Arc::new(Zeroizing::new(key.as_ref().to_vec()));

            let progress = Arc::new(AtomicU64::new(0));
            let done = Arc::new(AtomicBool::new(false));

            let progress_clone = Arc::clone(&progress);
            let done_clone = Arc::clone(&done);
            let progress_handle = thread::spawn(move || {
                loop {
                    thread::sleep(std::time::Duration::from_millis(500));
                    if done_clone.load(Ordering::Relaxed) {
                        print_progress_bar(total_input_size, total_input_size, true);
                        break;
                    }
                    let current = progress_clone.load(Ordering::Relaxed);
                    if current > 0 {
                        print_progress_bar(current, total_input_size, false);
                    }
                }
            });

            let pipe_reader_handle = thread::spawn(move || -> std::io::Result<()> {
                let mut pipe_buf = BufReader::new(pipe_reader);
                let mut chunk_index: u64 = 0;
                let mut chunk_data = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

                loop {
                    let mut buf_offset = 0usize;
                    loop {
                        match pipe_buf.read(&mut chunk_data[buf_offset..]) {
                            Ok(0) => break,
                            Ok(n) => buf_offset += n,
                            Err(e) => return Err(e),
                        }
                        if buf_offset >= CHUNK_SIZE { break; }
                    }

                    if buf_offset == 0 { break; }

                    let chunk = RawChunk {
                        index: chunk_index,
                        data: Zeroizing::new(chunk_data[..buf_offset].to_vec()),
                    };
                    if raw_tx.send(chunk).is_err() {
                        break;
                    }
                    chunk_data[..buf_offset].zeroize();
                    chunk_index += 1;
                }
                Ok(())
            });

            let mut worker_handles = Vec::new();
            for _ in 0..num_workers {
                let raw_rx = raw_rx.clone();
                let finished_tx = finished_tx.clone();
                let key_w = Arc::clone(&key_for_workers);
                let progress_w = Arc::clone(&progress);

                let handle = thread::spawn(move || -> std::io::Result<()> {
                    loop {
                        let raw = match raw_rx.recv() {
                            Ok(chunk) => chunk,
                            Err(_) => break,
                        };

                        let raw_index = raw.index;
                        let raw_len = raw.data.len() as u64;

                        let compressed = compress_frame(&raw.data)?;
                        let compressed_len = compressed.len() as u32;
                        // Drop 16 MB raw chunk before allocating encrypted output
                        drop(raw);

                        let encrypted = aes_encrypt(&compressed, &**key_w)?;
                        drop(compressed);

                        progress_w.fetch_add(raw_len, Ordering::SeqCst);

                        let finished = FinishedChunk {
                            index: raw_index,
                            compressed_len,
                            encrypted,
                        };
                        if finished_tx.send(finished).is_err() {
                            break;
                        }
                    }
                    Ok(())
                });
                worker_handles.push(handle);
            }

            // Drop the original finished_tx so the channel closes when all workers finish.
            // raw_tx is owned by the pipe reader thread and drops automatically.
            drop(finished_tx);

            // Writer reorders chunks by index. Cap pending to num_workers * 3 to prevent
            // unbounded memory growth if chunks arrive severely out of order.
            let mut output_file = BufWriter::with_capacity(8 * 1024 * 1024, File::create(&output_path)?);
            write_crypt_header(&mut output_file, key.as_ref(), salt.as_ref(), is_directory, &archive_name)?;

            let mut next_index: u64 = 0;
            let mut pending: HashMap<u64, FinishedChunk> = HashMap::new();
            let mut total_chunks: u64 = 0;

            while let Ok(finished) = finished_rx.recv() {
                if pending.len() >= num_workers * 3 {
                    while let Some(chunk) = pending.remove(&next_index) {
                        output_file.write_all(&chunk.compressed_len.to_le_bytes())?;
                        output_file.write_all(&chunk.encrypted)?;
                        next_index += 1;
                        total_chunks += 1;
                    }
                }

                pending.insert(finished.index, finished);

                while let Some(chunk) = pending.remove(&next_index) {
                    output_file.write_all(&chunk.compressed_len.to_le_bytes())?;
                    output_file.write_all(&chunk.encrypted)?;
                    next_index += 1;
                    total_chunks += 1;
                }
            }

            while let Some(chunk) = pending.remove(&next_index) {
                output_file.write_all(&chunk.compressed_len.to_le_bytes())?;
                output_file.write_all(&chunk.encrypted)?;
                next_index += 1;
                total_chunks += 1;
            }

            if !pending.is_empty() {
                eprintln!("[WARN] {} out-of-order chunks could not be written (gaps in sequence).", pending.len());
            }

            output_file.write_all(&0u32.to_le_bytes())?;
            output_file.flush()?;

            done.store(true, Ordering::SeqCst);

            pipe_reader_handle.join().unwrap().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("Pipe reader thread failed: {:?}", e))
            })?;

            for wh in worker_handles {
                wh.join().unwrap().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("Worker thread failed: {:?}", e))
                })?;
            }

            tar_handle.join().unwrap().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("Tar thread failed: {:?}", e))
            })?;

            progress_handle.join().unwrap();

            drop(key);
            drop(salt);

            let final_size = fs::metadata(&output_path).map(|m| m.len()).unwrap_or(0);
            println!("Encryption complete: {} ({} MB, {} chunks)", output_path.display(), final_size / (1024 * 1024), total_chunks);
        }

        'd' => {
            for input_path in &input_paths {
                println!("Decrypting {}...", input_path.display());
                if !input_path.is_file() {
                    eprintln!("Error: '{}' is not a valid .crypt file.", input_path.display());
                    continue;
                }

                let mut archive_file = File::open(input_path)?;
                let mut preader = BufReader::with_capacity(4096, &mut archive_file);

                let mut magic = [0u8; 4];
                if preader.read_exact(&mut magic).is_err() || &magic != CRYPT_MAGIC {
                    eprintln!("Error: '{}' is not a valid .crypt file (bad magic). Skipping.", input_path.display());
                    continue;
                }

                let mut version_bytes = [0u8; 2];
                if preader.read_exact(&mut version_bytes).is_err() { eprintln!("Error: '{}' is truncated. Skipping.", input_path.display()); continue; }
                let version = u16::from_le_bytes(version_bytes);
                if version < 1 || version > CRYPT_VERSION { eprintln!("Error: '{}' has unsupported version {}. Skipping.", input_path.display(), version); continue; }

                let mut salt = [0u8; SALT_SIZE];
                if preader.read_exact(&mut salt).is_err() { eprintln!("Error: '{}' is truncated (missing salt). Skipping.", input_path.display()); continue; }

                let mut header_len_bytes = [0u8; 2];
                if preader.read_exact(&mut header_len_bytes).is_err() { eprintln!("Error: '{}' is truncated (missing header). Skipping.", input_path.display()); continue; }
                let header_total_len = u16::from_le_bytes(header_len_bytes) as usize;

                let mut header_encrypted = vec![0u8; header_total_len];
                if preader.read_exact(&mut header_encrypted).is_err() { eprintln!("Error: '{}' is truncated (missing header data). Skipping.", input_path.display()); continue; }

                let salt_zero = Zeroizing::new(salt);
                let key = derive_key(&*decrypt_password, &salt_zero);

                let header_plaintext = match aes_decrypt(&header_encrypted, key.as_ref()) {
                    Ok(pt) => pt,
                    Err(e) => { eprintln!("Error decrypting '{}' header: {}. Wrong password or corrupted file. Skipping.", input_path.display(), e); continue; }
                };

                if header_plaintext.len() < 3 { eprintln!("Error: '{}' header too short. Skipping.", input_path.display()); continue; }

                let is_directory = header_plaintext[0] == b'D';
                let name_len = u16::from_le_bytes([header_plaintext[1], header_plaintext[2]]) as usize;
                let name_bytes = &header_plaintext[3..3 + name_len];
                let original_name = String::from_utf8_lossy(name_bytes).to_string();
                let safe_name = sanitize_filename(&original_name);

                let parent = output_dir.as_deref().unwrap_or(
                    input_path.parent().unwrap_or(Path::new("."))
                );
                let output_path_dir = parent.join(&safe_name);

                // Pipeline: Chunk reader (I/O) -> crossbeam (CPU workers) -> Pipe writer (I/O)

                let (raw_pipe_reader, raw_pipe_writer) = os_pipe::pipe()?;

                let crypt_path = input_path.to_owned();
                let key_thread = Arc::new(Zeroizing::new(key.as_ref().to_vec()));
                let header_skip = 4u64 + 2 + SALT_SIZE as u64 + 2 + header_total_len as u64;

                let total_file_size = fs::metadata(&crypt_path)?.len();
                let total_data_size = total_file_size.saturating_sub(header_skip);

                let (enc_tx, enc_rx) = crossbeam_channel::bounded::<EncryptedChunk>(num_workers);
                let (dec_tx, dec_rx) = crossbeam_channel::bounded::<DecryptedChunk>(num_workers * 2);

                let progress = Arc::new(AtomicU64::new(0));
                let done = Arc::new(AtomicBool::new(false));

                let progress_clone = Arc::clone(&progress);
                let done_clone = Arc::clone(&done);
                let progress_handle = thread::spawn(move || {
                    loop {
                        thread::sleep(std::time::Duration::from_millis(500));
                        if done_clone.load(Ordering::Relaxed) {
                            print_progress_bar(total_data_size, total_data_size, true);
                            break;
                        }
                        let current = progress_clone.load(Ordering::Relaxed);
                        if current > 0 {
                            print_progress_bar(current, total_data_size, false);
                        }
                    }
                });

                let chunk_reader_handle = thread::spawn(move || -> std::io::Result<()> {
                    use std::io::Seek;
                    let mut crypt_file = File::open(&crypt_path)?;
                    crypt_file.seek(std::io::SeekFrom::Start(header_skip))?;
                    let mut chunk_reader = BufReader::with_capacity(8 * 1024 * 1024, crypt_file);
                    let mut chunk_index: u64 = 0;

                    loop {
                        let mut pt_len_bytes = [0u8; 4];
                        match chunk_reader.read_exact(&mut pt_len_bytes) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                            Err(e) => return Err(e),
                        }
                        let pt_len = u32::from_le_bytes(pt_len_bytes) as usize;
                        if pt_len == 0 { break; }

                        let chunk_len = 12 + pt_len + 16;
                        let mut chunk_data = vec![0u8; chunk_len];
                        chunk_reader.read_exact(&mut chunk_data)?;

                        let chunk = EncryptedChunk {
                            index: chunk_index,
                            data: chunk_data,
                        };
                        if enc_tx.send(chunk).is_err() {
                            break;
                        }
                        chunk_index += 1;
                    }
                    Ok(())
                });

                let mut worker_handles = Vec::new();
                for _ in 0..num_workers {
                    let enc_rx = enc_rx.clone();
                    let dec_tx = dec_tx.clone();
                    let key_w = Arc::clone(&key_thread);
                    let progress_w = Arc::clone(&progress);

                    let handle = thread::spawn(move || -> std::io::Result<()> {
                        loop {
                            let chunk = match enc_rx.recv() {
                                Ok(c) => c,
                                Err(_) => break,
                            };

                            let compressed = aes_decrypt(&chunk.data, &**key_w).map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, "Chunk decryption failed.")
                            })?;

                            let raw = decompress_frame(&compressed)?;
                            let raw_len = raw.len() as u64;
                            drop(compressed);

                            progress_w.fetch_add(raw_len, Ordering::SeqCst);

                            let decrypted = DecryptedChunk {
                                index: chunk.index,
                                data: raw,
                            };
                            if dec_tx.send(decrypted).is_err() {
                                break;
                            }
                        }
                        Ok(())
                    });
                    worker_handles.push(handle);
                }

                drop(dec_tx);

                // Pipe writer uses BufWriter to batch chunks before flushing to the pipe.
                // Without this, each write_all blocks on the 64 KB kernel pipe buffer,
                // causing backpressure that starves the worker threads.
                let pipe_writer_handle = thread::spawn(move || -> std::io::Result<()> {
                    let mut pipe_buf = BufWriter::with_capacity(8 * 1024 * 1024, raw_pipe_writer);
                    let mut next_index: u64 = 0;
                    let mut pending: HashMap<u64, DecryptedChunk> = HashMap::new();

                    while let Ok(decrypted) = dec_rx.recv() {
                        if pending.len() >= num_workers * 3 {
                            while let Some(chunk) = pending.remove(&next_index) {
                                pipe_buf.write_all(&chunk.data)?;
                                next_index += 1;
                            }
                        }

                        pending.insert(decrypted.index, decrypted);

                        while let Some(chunk) = pending.remove(&next_index) {
                            pipe_buf.write_all(&chunk.data)?;
                            next_index += 1;
                        }
                    }

                    while let Some(chunk) = pending.remove(&next_index) {
                        pipe_buf.write_all(&chunk.data)?;
                        next_index += 1;
                    }

                    if !pending.is_empty() {
                        eprintln!("[WARN] {} out-of-order decrypted chunks could not be written.", pending.len());
                    }

                    pipe_buf.flush()?;
                    drop(pipe_buf);
                    Ok(())
                });

                if is_directory {
                    fs::create_dir_all(&output_path_dir)?;
                    let mut archive = tar::Archive::new(BufReader::with_capacity(8 * 1024 * 1024, raw_pipe_reader));
                    unpack_tar_sanitized(&mut archive, &output_path_dir)?;
                } else {
                    if let Some(parent_dir) = output_path_dir.parent() {
                        if !parent_dir.as_os_str().is_empty() { fs::create_dir_all(parent_dir)?; }
                    }
                    let mut archive = tar::Archive::new(BufReader::with_capacity(8 * 1024 * 1024, raw_pipe_reader));
                    let mut entries: Vec<_> = archive.entries()?.filter_map(|e| e.ok()).collect();
                    if entries.is_empty() {
                        eprintln!("[WARN] No entries found in decrypted tar for '{}'.", input_path.display());
                    } else {
                        let mut entry = entries.remove(0);
                        let mut output_file = File::create(&output_path_dir)?;
                        std::io::copy(&mut entry, &mut output_file)?;
                    }
                }

                done.store(true, Ordering::SeqCst);

                chunk_reader_handle.join().unwrap().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("Chunk reader thread failed: {:?}", e))
                })?;

                for wh in worker_handles {
                    wh.join().unwrap().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Decrypt worker thread failed: {:?}", e))
                    })?;
                }

                pipe_writer_handle.join().unwrap().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("Pipe writer thread failed: {:?}", e))
                })?;

                progress_handle.join().unwrap();

                println!("Decrypted into: {}", output_path_dir.display());
            }

        }

        _ => unreachable!(),
    }

    Ok(())
}