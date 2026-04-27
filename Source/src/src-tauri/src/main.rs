#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    AesGcm,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use flate2::{write::ZlibEncoder, Compression};
use rand::RngCore;
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs,
    io::Write,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use typenum::U16;
use walkdir::WalkDir;

type AccountCipher = AesGcm<aes::Aes256, U16>;
type AppResult = Result<Value, String>;

const HYDRO_START: u16 = 6969;
const HYDRO_END: u16 = 7069;
const MACSPLOIT_START: u16 = 5553;
const MACSPLOIT_END: u16 = 5563;
const OPIUM_START: u16 = 8392;
const OPIUM_END: u16 = 8397;
#[derive(Clone)]
struct AppStateHandle {
    inner: Arc<AppState>,
}

struct AppState {
    paths: AppPaths,
    log_refresh_rate: Mutex<f64>,
    log_monitor_stop: Mutex<Option<Arc<AtomicBool>>>,
}

#[derive(Clone)]
struct AppPaths {
    directory: PathBuf,
    scripts_directory: PathBuf,
    accounts_directory: PathBuf,
    accounts_file: PathBuf,
    metadata_file: PathBuf,
    hydrogen_autoexec_dir: PathBuf,
    macsploit_autoexec_dir: PathBuf,
    opiumware_autoexec_dir: PathBuf,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredAccount {
    cookie: String,
    #[serde(rename = "userId")]
    user_id: u64,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
    thumbnail: String,
    #[serde(rename = "addedAt")]
    added_at: String,
}

#[derive(Clone, Serialize)]
struct DisplayAccount {
    #[serde(flatten)]
    account: StoredAccount,
    expired: bool,
}

impl AppStateHandle {
    fn new() -> Result<Self, String> {
        let home_dir = home_dir()?;
        let directory = home_dir.join("JewWare");
        let scripts_directory = directory.join("scripts");
        let accounts_directory = directory.join("accounts");
        let accounts_file = accounts_directory.join("accounts.dat");
        let metadata_file = directory.join("metadata.json");
        let hydrogen_autoexec_dir = home_dir.join("Hydrogen").join("autoexecute");
        let macsploit_autoexec_dir = home_dir
            .join("Documents")
            .join("Macsploit Automatic Execution");
        let opiumware_autoexec_dir = home_dir.join("Opiumware").join("autoexec");

        let paths = AppPaths {
            directory,
            scripts_directory,
            accounts_directory,
            accounts_file,
            metadata_file,
            hydrogen_autoexec_dir,
            macsploit_autoexec_dir,
            opiumware_autoexec_dir,
        };

        ensure_directories(&paths)?;
        sync_autoexec_folders(&paths)?;

        Ok(Self {
            inner: Arc::new(AppState {
                paths,
                log_refresh_rate: Mutex::new(0.5),
                log_monitor_stop: Mutex::new(None),
            }),
        })
    }
}

fn home_dir() -> Result<PathBuf, String> {
    env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| "Unable to resolve the HOME directory".to_string())
}

fn ensure_directories(paths: &AppPaths) -> Result<(), String> {
    fs::create_dir_all(&paths.directory).map_err(|e| e.to_string())?;
    fs::create_dir_all(&paths.scripts_directory).map_err(|e| e.to_string())?;
    fs::create_dir_all(&paths.accounts_directory).map_err(|e| e.to_string())?;
    Ok(())
}

fn supported_script_extension(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref(),
        Some("lua") | Some("txt")
    )
}

fn sanitize_script_component(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | ' ' | '_' | '-'))
        .collect::<String>()
}

fn normalize_script_file_name(file_name: &str, default_extension: &str) -> String {
    let raw_name = if file_name.trim().is_empty() {
        "script"
    } else {
        file_name.trim()
    };
    let base_name = Path::new(raw_name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("script");
    let cleaned = sanitize_script_component(base_name);
    let cleaned = if cleaned.trim().is_empty() {
        "script".to_string()
    } else {
        cleaned
    };
    let cleaned_path = Path::new(&cleaned);
    let current_ext = cleaned_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
        .unwrap_or_default();
    let extension = match current_ext.as_str() {
        ".lua" | ".txt" => current_ext,
        _ => default_extension.to_string(),
    };
    let stem = cleaned_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("script")
        .trim_end_matches('.')
        .trim();
    let stem = if stem.is_empty() { "script" } else { stem };
    format!("{stem}{extension}")
}

fn make_unique_script_file_name(directory: &Path, desired_name: &str) -> String {
    let normalized = normalize_script_file_name(desired_name, ".lua");
    let extension = Path::new(&normalized)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();
    let stem = if extension.is_empty() {
        normalized.clone()
    } else {
        normalized.trim_end_matches(&extension).to_string()
    };

    let mut candidate = normalized.clone();
    let mut counter = 2;
    while directory.join(&candidate).exists() {
        candidate = format!("{stem}-{counter}{extension}");
        counter += 1;
    }
    candidate
}

fn autoexec_directories(paths: &AppPaths) -> [PathBuf; 3] {
    [
        paths.hydrogen_autoexec_dir.clone(),
        paths.macsploit_autoexec_dir.clone(),
        paths.opiumware_autoexec_dir.clone(),
    ]
}

fn sync_autoexec_folders(paths: &AppPaths) -> Result<(), String> {
    let directories = autoexec_directories(paths)
        .into_iter()
        .filter(|directory| directory.exists())
        .collect::<Vec<_>>();

    if directories.is_empty() {
        return Ok(());
    }

    let mut all_scripts = std::collections::BTreeMap::new();
    for directory in &directories {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("lua") {
                continue;
            }
            if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
                if let Ok(content) = fs::read_to_string(&path) {
                    all_scripts.entry(file_name.to_string()).or_insert(content);
                }
            }
        }
    }

    for (script_name, content) in all_scripts {
        for directory in &directories {
            let target = directory.join(&script_name);
            if !target.exists() {
                let _ = fs::write(target, &content);
            }
        }
    }

    Ok(())
}

fn script_entry_json(paths: &AppPaths, file_path: &Path) -> Option<Value> {
    let file_name = file_path.file_name()?.to_str()?.to_string();
    let content = fs::read_to_string(file_path).ok()?;
    let is_lua = file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("lua"))
        .unwrap_or(false);
    let auto_exec = is_lua
        && autoexec_directories(paths)
            .iter()
            .any(|directory| directory.join(&file_name).exists());

    Some(json!({
        "name": file_name,
        "path": file_path.to_string_lossy().to_string(),
        "content": content,
        "type": file_path.extension().and_then(|ext| ext.to_str()).unwrap_or_default().to_ascii_lowercase(),
        "autoExec": auto_exec
    }))
}

fn write_autoexec_files(paths: &AppPaths, file_name: &str, content: &str, enabled: bool) {
    for directory in autoexec_directories(paths) {
        let autoexec_path = directory.join(file_name);
        if enabled && directory.exists() {
            let _ = fs::write(&autoexec_path, content);
        } else if autoexec_path.exists() {
            let _ = fs::remove_file(autoexec_path);
        }
    }
}

fn save_script_internal(
    state: &AppStateHandle,
    name: String,
    content: String,
    auto_exec: bool,
    silent: bool,
) -> AppResult {
    ensure_directories(&state.inner.paths)?;

    let normalized_name = normalize_script_file_name(&name, ".lua");
    let is_lua = normalized_name.ends_with(".lua");
    let final_auto_exec = is_lua && auto_exec;
    let file_path = state.inner.paths.scripts_directory.join(&normalized_name);

    fs::write(&file_path, content.as_bytes()).map_err(|e| e.to_string())?;
    write_autoexec_files(&state.inner.paths, &normalized_name, &content, final_auto_exec);

    Ok(json!({
        "status": "success",
        "message": if silent {
            format!("Autosaved {normalized_name}")
        } else {
            format!("Script saved to {}", file_path.to_string_lossy())
        },
        "path": file_path.to_string_lossy().to_string(),
        "autoExec": final_auto_exec
    }))
}

fn http_client(timeout_secs: u64) -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| e.to_string())
}

fn execute_script_via_macsploit(script_content: &str, port: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}")
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?,
        Duration::from_secs(3),
    )
    .map_err(|e| e.to_string())?;
    let mut header = vec![0_u8; 16];
    let payload_len = (script_content.len() + 1) as u32;
    header[8..12].copy_from_slice(&payload_len.to_le_bytes());
    let mut payload = header;
    payload.extend_from_slice(script_content.as_bytes());
    payload.push(0);
    stream.write_all(&payload).map_err(|e| e.to_string())
}

fn execute_script_via_opium(script_content: &str, port: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}")
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?,
        Duration::from_secs(3),
    )
    .map_err(|e| e.to_string())?;
    let formatted_script = format!("OpiumwareScript {script_content}");
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(formatted_script.as_bytes())
        .map_err(|e| e.to_string())?;
    let compressed = encoder.finish().map_err(|e| e.to_string())?;
    stream.write_all(&compressed).map_err(|e| e.to_string())
}

fn execute_script_internal(script_content: &str) -> AppResult {
    let client = http_client(2)?;

    for port in HYDRO_START..=HYDRO_END {
        let secret_url = format!("http://127.0.0.1:{port}/secret");
        if let Ok(response) = client.get(secret_url).send() {
            if response.status().is_success() {
                if let Ok(body) = response.text() {
                    if body == "0xdeadbeef" {
                        let execute_url = format!("http://127.0.0.1:{port}/execute");
                        if let Ok(response) = client
                            .post(execute_url)
                            .header("Content-Type", "text/plain")
                            .header("User-Agent", "JewWare/6.1")
                            .body(script_content.to_string())
                            .send()
                        {
                            if response.status().is_success() {
                                return Ok(json!({
                                    "status": "success",
                                    "message": "Script executed successfully via Hydrogen"
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    for port in OPIUM_START..=OPIUM_END {
        if execute_script_via_opium(script_content, port).is_ok() {
            return Ok(json!({
                "status": "success",
                "message": format!("Script executed successfully via OpiumWare on port {port}")
            }));
        }
    }

    let mut working_ports = Vec::new();
    for port in MACSPLOIT_START..=MACSPLOIT_END {
        if execute_script_via_macsploit(script_content, port).is_ok() {
            working_ports.push(port);
        }
    }

    if !working_ports.is_empty() {
        return Ok(json!({
            "status": "success",
            "message": format!(
                "Script executed successfully via MacSploit on port(s): {}",
                working_ports
                    .iter()
                    .map(|port| port.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }));
    }

    Ok(json!({
        "status": "error",
        "message": "Error: No compatible executor detected. Make sure Roblox is running and a compatible executor is installed."
    }))
}

fn current_version() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

fn get_encryption_key() -> [u8; 32] {
    let machine_id = format!(
        "{}-{}-jewware-accounts-v1",
        env::var("USER").unwrap_or_else(|_| "user".to_string()),
        "darwin"
    );
    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

fn encrypt_accounts(accounts: &[StoredAccount]) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = AccountCipher::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut iv = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = GenericArray::from_slice(&iv);
    let plaintext = serde_json::to_vec(accounts).map_err(|e| e.to_string())?;
    let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|e| e.to_string())?;
    if encrypted.len() < 16 {
        return Err("Encrypted data is unexpectedly short".to_string());
    }
    let split_index = encrypted.len() - 16;
    let ciphertext = &encrypted[..split_index];
    let auth_tag = &encrypted[split_index..];
    Ok(format!(
        "{}:{}:{}",
        BASE64.encode(iv),
        BASE64.encode(auth_tag),
        BASE64.encode(ciphertext)
    ))
}

fn decrypt_accounts(content: &str) -> Result<Vec<StoredAccount>, String> {
    let parts = content.split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err("Invalid encrypted data format".to_string());
    }
    let key = get_encryption_key();
    let cipher = AccountCipher::new_from_slice(&key).map_err(|e| e.to_string())?;
    let iv = BASE64.decode(parts[0]).map_err(|e| e.to_string())?;
    let auth_tag = BASE64.decode(parts[1]).map_err(|e| e.to_string())?;
    let ciphertext = BASE64.decode(parts[2]).map_err(|e| e.to_string())?;
    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);
    let nonce = GenericArray::from_slice(&iv);
    let decrypted = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&decrypted).map_err(|e| e.to_string())
}

fn is_encrypted(content: &str) -> bool {
    let parts = content.split(':').collect::<Vec<_>>();
    parts.len() == 3 && parts.iter().all(|part| !part.is_empty() && BASE64.decode(part).is_ok())
}

fn load_accounts(state: &AppStateHandle) -> Vec<StoredAccount> {
    if !state.inner.paths.accounts_file.exists() {
        return Vec::new();
    }
    let content = match fs::read_to_string(&state.inner.paths.accounts_file) {
        Ok(content) => content.trim().to_string(),
        Err(_) => return Vec::new(),
    };
    if content.is_empty() {
        return Vec::new();
    }
    if is_encrypted(&content) {
        return decrypt_accounts(&content).unwrap_or_default();
    }
    if let Ok(accounts) = serde_json::from_str::<Vec<StoredAccount>>(&content) {
        let _ = save_accounts(state, &accounts);
        return accounts;
    }
    Vec::new()
}

fn save_accounts(state: &AppStateHandle, accounts: &[StoredAccount]) -> Result<(), String> {
    ensure_directories(&state.inner.paths)?;
    let encrypted = encrypt_accounts(accounts)?;
    fs::write(&state.inner.paths.accounts_file, encrypted).map_err(|e| e.to_string())
}

fn roblox_client(timeout_secs: u64, cookie: Option<&str>) -> Result<Client, String> {
    let mut builder = Client::builder().timeout(Duration::from_secs(timeout_secs));
    if let Some(cookie) = cookie {
        let mut headers = reqwest::header::HeaderMap::new();
        let cookie_header = format!(".ROBLOSECURITY={cookie}");
        headers.insert(
            reqwest::header::COOKIE,
            reqwest::header::HeaderValue::from_str(&cookie_header).map_err(|e| e.to_string())?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ),
        );
        builder = builder.default_headers(headers);
    }
    builder.build().map_err(|e| e.to_string())
}

fn get_roblox_profile(cookie: &str) -> Result<(u64, String, String), String> {
    let client = roblox_client(10, Some(cookie))?;
    let response = client
        .get("https://users.roblox.com/v1/users/authenticated")
        .send()
        .map_err(|e| e.to_string())?;
    if response.status().as_u16() == 403 || response.status().as_u16() == 401 {
        return Err("FORBIDDEN".to_string());
    }
    let payload = response.json::<Value>().map_err(|e| e.to_string())?;
    let user_id = payload
        .get("id")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| "Missing Roblox user id".to_string())?;
    let name = payload
        .get("name")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let display_name = payload
        .get("displayName")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    Ok((user_id, name, display_name))
}

fn get_roblox_thumbnail(user_id: u64, retries: usize) -> Result<String, String> {
    let client = roblox_client(10, None)?;
    let url = format!("https://thumbnails.roblox.com/v1/users/avatar-bust?userIds={user_id}&size=150x150&format=Png&isCircular=true");
    let payload = client
        .get(url)
        .send()
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .map_err(|e| e.to_string())?;

    if let Some(entry) = payload
        .get("data")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
    {
        let state = entry.get("state").and_then(|value| value.as_str()).unwrap_or_default();
        if state == "Pending" && retries > 0 {
            thread::sleep(Duration::from_millis(1500));
            return get_roblox_thumbnail(user_id, retries - 1);
        }
        if state == "Completed" {
            if let Some(url) = entry.get("imageUrl").and_then(|value| value.as_str()) {
                return Ok(url.to_string());
            }
        }
    }

    Ok(format!(
        "https://www.roblox.com/headshot-thumbnail/image?userId={user_id}&width=150&height=150&format=png"
    ))
}

fn get_roblox_user_data(cookie: &str) -> Result<StoredAccount, String> {
    let (user_id, name, display_name) = get_roblox_profile(cookie)?;
    let thumbnail = get_roblox_thumbnail(user_id, 3)?;
    Ok(StoredAccount {
        cookie: cookie.to_string(),
        user_id,
        name,
        display_name,
        thumbnail,
        added_at: Utc::now().to_rfc3339(),
    })
}

fn to_cocoa_timestamp(unix_millis: i64) -> f64 {
    (unix_millis as f64 / 1000.0) - 978_307_200.0
}

fn build_binary_cookies(cookie_value: &str) -> Vec<u8> {
    let now = Utc::now().timestamp_millis();
    let expiration_date = now + (30_i64 * 24 * 60 * 60 * 1000);
    let creation_time = to_cocoa_timestamp(now);
    let expiration_time = to_cocoa_timestamp(expiration_date);

    let domain = ".roblox.com\0".as_bytes().to_vec();
    let name = ".ROBLOSECURITY\0".as_bytes().to_vec();
    let path_bytes = "/\0".as_bytes().to_vec();
    let mut value_bytes = cookie_value.as_bytes().to_vec();
    value_bytes.push(0);

    let domain_offset = 56_u32;
    let name_offset = domain_offset + domain.len() as u32;
    let path_offset = name_offset + name.len() as u32;
    let value_offset = path_offset + path_bytes.len() as u32;
    let cookie_size = value_offset + value_bytes.len() as u32;
    let flags = 0x5_u32;

    let mut cookie_buffer = Vec::with_capacity(cookie_size as usize);
    cookie_buffer.extend_from_slice(&cookie_size.to_le_bytes());
    cookie_buffer.extend_from_slice(&1_u32.to_le_bytes());
    cookie_buffer.extend_from_slice(&flags.to_le_bytes());
    cookie_buffer.extend_from_slice(&0_u32.to_le_bytes());
    cookie_buffer.extend_from_slice(&domain_offset.to_le_bytes());
    cookie_buffer.extend_from_slice(&name_offset.to_le_bytes());
    cookie_buffer.extend_from_slice(&path_offset.to_le_bytes());
    cookie_buffer.extend_from_slice(&value_offset.to_le_bytes());
    cookie_buffer.extend_from_slice(&0_u32.to_le_bytes());
    cookie_buffer.extend_from_slice(&0_u32.to_le_bytes());
    cookie_buffer.extend_from_slice(&expiration_time.to_le_bytes());
    cookie_buffer.extend_from_slice(&creation_time.to_le_bytes());
    cookie_buffer.extend_from_slice(&domain);
    cookie_buffer.extend_from_slice(&name);
    cookie_buffer.extend_from_slice(&path_bytes);
    cookie_buffer.extend_from_slice(&value_bytes);

    let mut page_data = Vec::new();
    page_data.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    page_data.extend_from_slice(&1_u32.to_le_bytes());
    page_data.extend_from_slice(&12_u32.to_le_bytes());
    page_data.extend_from_slice(&cookie_buffer);

    let mut checksum = 0_u32;
    let mut index = 0_usize;
    while index < page_data.len() {
        checksum = checksum.wrapping_add(page_data[index] as u32);
        index += 4;
    }

    let mut file_data = Vec::new();
    file_data.extend_from_slice(&[0x63, 0x6F, 0x6F, 0x6B]);
    file_data.extend_from_slice(&1_u32.to_be_bytes());
    file_data.extend_from_slice(&(page_data.len() as u32).to_be_bytes());
    file_data.extend_from_slice(&page_data);
    file_data.extend_from_slice(&checksum.to_be_bytes());
    file_data.extend_from_slice(&[0x07, 0x17, 0x20, 0x05, 0x00, 0x00, 0x00, 0x4B]);
    file_data
}

fn write_roblox_cookie(cookie_value: &str, profile_id: &str) -> Result<PathBuf, String> {
    let home_dir = home_dir()?;
    let cookie_file = home_dir
        .join("Library")
        .join("HTTPStorages")
        .join(format!("com.roblox.RobloxPlayer.{profile_id}.binarycookies"));
    if let Some(parent) = cookie_file.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&cookie_file, build_binary_cookies(cookie_value)).map_err(|e| e.to_string())?;
    Ok(cookie_file)
}

fn modify_bundle_identifier(roblox_app_path: &Path, profile_id: &str) -> Result<(), String> {
    let plist_path = roblox_app_path.join("Contents").join("Info.plist");
    let plist_content = fs::read_to_string(&plist_path).map_err(|e| e.to_string())?;
    let bundle_id_regex = Regex::new(
        r"(?s)<key>CFBundleIdentifier</key>\s*<string>com\.roblox\.RobloxPlayer(?:\.\w+)?</string>",
    )
    .map_err(|e| e.to_string())?;
    if !bundle_id_regex.is_match(&plist_content) {
        return Err("Could not find CFBundleIdentifier in Info.plist".to_string());
    }
    let replacement = format!(
        "<key>CFBundleIdentifier</key>\n\t<string>com.roblox.RobloxPlayer.{profile_id}</string>"
    );
    let updated = bundle_id_regex.replace(&plist_content, replacement);
    fs::write(plist_path, updated.as_bytes()).map_err(|e| e.to_string())
}

fn reset_bundle_identifier(roblox_app_path: &Path) -> Result<(), String> {
    let plist_path = roblox_app_path.join("Contents").join("Info.plist");
    if !plist_path.exists() {
        return Ok(());
    }
    let plist_content = fs::read_to_string(&plist_path).map_err(|e| e.to_string())?;
    let bundle_id_regex = Regex::new(
        r"(?s)<key>CFBundleIdentifier</key>\s*<string>com\.roblox\.RobloxPlayer(?:\.\w+)?</string>",
    )
    .map_err(|e| e.to_string())?;
    let replacement = "<key>CFBundleIdentifier</key>\n\t<string>com.roblox.RobloxPlayer</string>";
    let updated = bundle_id_regex.replace(&plist_content, replacement);
    fs::write(plist_path, updated.as_bytes()).map_err(|e| e.to_string())
}

fn emit_to_main(app: &AppHandle, event: &str, payload: Value) {
    let _ = app.emit_to("main", event, payload);
}

#[tauri::command]
fn get_version() -> AppResult {
    Ok(json!({ "version": current_version() }))
}

#[tauri::command]
fn open_scripts_folder(state: State<'_, AppStateHandle>) -> AppResult {
    Command::new("open")
        .arg(&state.inner.paths.scripts_directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(json!({ "status": "success" }))
}

#[tauri::command]
fn execute_script(script_content: String) -> AppResult {
    execute_script_internal(&script_content)
}

#[tauri::command]
fn execute_script_on_port(script_content: String, target_port: Option<String>) -> AppResult {
    if target_port.as_deref().unwrap_or("auto") == "auto" {
        return execute_script_internal(&script_content);
    }
    let port = target_port
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|e| e.to_string())?;
    execute_script_via_macsploit(&script_content, port).map_err(|e| {
        format!("Error: Failed to execute on port {port}. Make sure the instance is running. {e}")
    })?;
    Ok(json!({
        "status": "success",
        "message": format!("Script executed successfully via MacSploit on port {port}"),
        "details": []
    }))
}

#[tauri::command]
fn check_port_status() -> AppResult {
    let mut ports = Vec::new();
    for port in MACSPLOIT_START..=MACSPLOIT_END {
        let online = execute_script_via_macsploit("-- ping", port).is_ok();
        ports.push(json!({
            "port": port,
            "type": "macsploit",
            "online": online,
            "label": format!("MacSploit :{port}")
        }));
    }
    Ok(Value::Array(ports))
}

#[tauri::command]
fn get_game_name(universe_id: String) -> AppResult {
    let client = http_client(10)?;
    let url = format!("https://games.roblox.com/v1/games?universeIds={universe_id}");
    let payload = client
        .get(url)
        .send()
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .map_err(|e| e.to_string())?;
    if let Some(game_name) = payload
        .get("data")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .and_then(|entry| entry.get("name"))
        .and_then(|value| value.as_str())
    {
        Ok(json!({ "status": "success", "game_name": game_name }))
    } else {
        Ok(json!({ "status": "error", "message": "Game not found" }))
    }
}

#[tauri::command]
fn get_scripts(script: String) -> AppResult {
    let client = http_client(20)?;
    let url = if script.trim().is_empty() {
        "https://scriptblox.com/api/script/fetch".to_string()
    } else {
        format!(
            "https://scriptblox.com/api/script/search?q={}",
            urlencoding::encode(script.trim())
        )
    };
    client
        .get(url)
        .send()
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn open_roblox() -> AppResult {
    let app_paths = [
        PathBuf::from("/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"),
        home_dir()?.join("Applications/Roblox.app/Contents/MacOS/RobloxPlayer"),
    ];
    let roblox_exec = app_paths
        .into_iter()
        .find(|path| path.exists())
        .ok_or_else(|| "Roblox not found. Please install Roblox first.".to_string())?;
    Command::new(roblox_exec)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "status": "success",
        "message": "Roblox instance launched successfully"
    }))
}

fn get_website_path(app: &AppHandle) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join("website").join("index.html"));
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tauri-dist/website/index.html"));
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../website/index.html"));
    candidates.into_iter().find(|candidate| candidate.exists())
}

#[tauri::command]
fn join_website(app: AppHandle) -> AppResult {
    let website_path = get_website_path(&app)
        .ok_or_else(|| "JewWare website files were not found".to_string())?;
    Command::new("open")
        .arg(website_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(json!({ "status": "success", "message": "Website opened successfully" }))
}

#[derive(Deserialize)]
struct SaveOptions {
    silent: Option<bool>,
}

#[tauri::command]
fn save_script(
    state: State<'_, AppStateHandle>,
    name: String,
    content: String,
    auto_exec: Option<bool>,
    options: Option<SaveOptions>,
) -> AppResult {
    save_script_internal(
        &state,
        name,
        content,
        auto_exec.unwrap_or(false),
        options.and_then(|value| value.silent).unwrap_or(false),
    )
}

#[tauri::command]
fn toggle_autoexec(state: State<'_, AppStateHandle>, script_name: String, enabled: bool) -> AppResult {
    let script_path = state.inner.paths.scripts_directory.join(&script_name);
    if !script_path.exists() {
        return Ok(json!({ "status": "error", "message": format!("Script {script_name} not found") }));
    }
    let content = fs::read_to_string(&script_path).map_err(|e| e.to_string())?;
    write_autoexec_files(&state.inner.paths, &script_name, &content, enabled);
    Ok(json!({
        "status": "success",
        "message": format!("Auto-execute {} for {}", if enabled { "enabled" } else { "disabled" }, script_name)
    }))
}

#[tauri::command]
fn get_local_scripts(state: State<'_, AppStateHandle>) -> AppResult {
    ensure_directories(&state.inner.paths)?;
    let entries = fs::read_dir(&state.inner.paths.scripts_directory).map_err(|e| e.to_string())?;
    let scripts = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && supported_script_extension(path))
        .filter_map(|path| script_entry_json(&state.inner.paths, &path))
        .collect::<Vec<_>>();
    Ok(json!({ "status": "success", "scripts": scripts }))
}

#[tauri::command]
fn delete_script(state: State<'_, AppStateHandle>, script_name: String) -> AppResult {
    let script_path = state.inner.paths.scripts_directory.join(&script_name);
    if !script_path.exists() {
        return Ok(json!({ "status": "error", "message": format!("Script \"{script_name}\" not found") }));
    }
    fs::remove_file(&script_path).map_err(|e| e.to_string())?;
    for directory in autoexec_directories(&state.inner.paths) {
        let autoexec_path = directory.join(&script_name);
        if autoexec_path.exists() {
            let _ = fs::remove_file(autoexec_path);
        }
    }
    Ok(json!({
        "status": "success",
        "message": format!("Script \"{script_name}\" deleted successfully")
    }))
}

#[tauri::command]
fn rename_script(state: State<'_, AppStateHandle>, old_name: String, new_name: String) -> AppResult {
    let normalized_name = normalize_script_file_name(&new_name, ".lua");
    let old_path = state.inner.paths.scripts_directory.join(&old_name);
    let new_path = state.inner.paths.scripts_directory.join(&normalized_name);

    if !old_path.exists() {
        return Ok(json!({ "status": "error", "message": format!("Script \"{old_name}\" not found") }));
    }
    if new_path.exists() && old_name != normalized_name {
        return Ok(json!({ "status": "error", "message": format!("Script \"{normalized_name}\" already exists") }));
    }

    fs::rename(&old_path, &new_path).map_err(|e| e.to_string())?;
    let content = fs::read_to_string(&new_path).map_err(|e| e.to_string())?;

    for directory in autoexec_directories(&state.inner.paths) {
        let old_autoexec_path = directory.join(&old_name);
        let new_autoexec_path = directory.join(&normalized_name);
        if old_autoexec_path.exists() {
            let _ = fs::write(&new_autoexec_path, &content);
            let _ = fs::remove_file(&old_autoexec_path);
        }
    }

    Ok(json!({
        "status": "success",
        "message": format!("Script renamed from \"{old_name}\" to \"{normalized_name}\"")
    }))
}

#[tauri::command]
fn import_script_folder(state: State<'_, AppStateHandle>) -> AppResult {
    ensure_directories(&state.inner.paths)?;
    let Some(source_directory) = rfd::FileDialog::new().pick_folder() else {
        return Ok(json!({ "status": "cancelled", "count": 0, "scripts": [] }));
    };

    let file_paths = WalkDir::new(&source_directory)
        .into_iter()
        .flatten()
        .map(|entry| entry.into_path())
        .filter(|path| path.is_file() && supported_script_extension(path))
        .collect::<Vec<_>>();

    if file_paths.is_empty() {
        return Ok(json!({
            "status": "error",
            "message": "No .lua or .txt files were found in the selected folder.",
            "count": 0,
            "scripts": []
        }));
    }

    let mut imported_scripts = Vec::new();
    for file_path in file_paths {
        let content = fs::read_to_string(&file_path).map_err(|e| e.to_string())?;
        let file_name = file_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("script.lua");
        let target_name = make_unique_script_file_name(&state.inner.paths.scripts_directory, file_name);
        let target_path = state.inner.paths.scripts_directory.join(&target_name);
        fs::write(&target_path, &content).map_err(|e| e.to_string())?;
        imported_scripts.push(json!({
            "name": target_name,
            "path": target_path.to_string_lossy().to_string(),
            "sourcePath": file_path.to_string_lossy().to_string(),
            "content": content,
            "autoExec": false
        }));
    }

    Ok(json!({
        "status": "success",
        "count": imported_scripts.len(),
        "scripts": imported_scripts,
        "directory": source_directory.to_string_lossy().to_string()
    }))
}

#[tauri::command]
fn quit_app(app: AppHandle) -> AppResult {
    app.exit(0);
    Ok(json!({ "status": "success" }))
}

#[tauri::command]
fn minimize_app(window: WebviewWindow) -> AppResult {
    window.minimize().map_err(|e| e.to_string())?;
    Ok(json!({ "status": "success" }))
}

#[tauri::command]
fn toggle_fullscreen(window: WebviewWindow) -> AppResult {
    let next_state = !window.is_fullscreen().map_err(|e| e.to_string())?;
    window.set_fullscreen(next_state).map_err(|e| e.to_string())?;
    let _ = window.emit("fullscreen-changed", next_state);
    Ok(json!({ "status": "success", "isFullScreen": next_state }))
}

#[tauri::command]
fn get_latest_release_info() -> AppResult {
    let version = current_version();
    Ok(json!({
        "status": "success",
        "version": version,
        "name": "JewWare",
        "description": "JewWare release notes are not configured yet.\n\nBuild and package the app locally for now.",
        "published_at": "",
        "html_url": "",
        "isOutdated": false,
        "latestVersion": current_version(),
        "allReleases": [{
            "version": current_version(),
            "name": "JewWare",
            "description": "JewWare release notes are not configured yet.\n\nBuild and package the app locally for now.",
            "published_at": "",
            "html_url": ""
        }],
        "currentReleaseIndex": 0
    }))
}

#[tauri::command]
fn get_metadata(state: State<'_, AppStateHandle>) -> AppResult {
    if !state.inner.paths.metadata_file.exists() {
        return Ok(json!({ "status": "new", "data": { "theme": "diamond" } }));
    }
    let metadata = fs::read_to_string(&state.inner.paths.metadata_file)
        .ok()
        .and_then(|contents| serde_json::from_str::<Value>(&contents).ok())
        .unwrap_or_else(|| json!({ "theme": "diamond" }));
    Ok(json!({ "status": "success", "data": metadata }))
}

#[tauri::command]
fn save_metadata(state: State<'_, AppStateHandle>, metadata: Value) -> AppResult {
    fs::write(
        &state.inner.paths.metadata_file,
        serde_json::to_string_pretty(&metadata).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({ "status": "success" }))
}

#[tauri::command]
fn get_accounts(state: State<'_, AppStateHandle>) -> AppResult {
    let accounts = load_accounts(&state);
    let mut updated_accounts = Vec::new();
    let mut changed = false;

    for account in accounts {
        match get_roblox_user_data(&account.cookie) {
            Ok(fresh) => {
                let needs_update = account.name != fresh.name
                    || account.display_name != fresh.display_name
                    || account.thumbnail != fresh.thumbnail;
                if needs_update {
                    changed = true;
                }
                updated_accounts.push(DisplayAccount {
                    account: StoredAccount {
                        added_at: account.added_at.clone(),
                        ..fresh
                    },
                    expired: false,
                });
            }
            Err(_) => updated_accounts.push(DisplayAccount {
                account,
                expired: true,
            }),
        }
    }

    if changed {
        let persisted = updated_accounts
            .iter()
            .map(|item| item.account.clone())
            .collect::<Vec<_>>();
        let _ = save_accounts(&state, &persisted);
    }

    serde_json::to_value(updated_accounts).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_account(state: State<'_, AppStateHandle>, user_id: u64) -> AppResult {
    let accounts = load_accounts(&state)
        .into_iter()
        .filter(|account| account.user_id != user_id)
        .collect::<Vec<_>>();
    save_accounts(&state, &accounts)?;
    serde_json::to_value(accounts).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_accounts(state: State<'_, AppStateHandle>) -> AppResult {
    let accounts = load_accounts(&state);
    if accounts.is_empty() {
        return Err("No accounts to export".to_string());
    }
    let Some(file_path) = rfd::FileDialog::new()
        .set_file_name("jewware-accounts.json")
        .save_file() else {
        return Ok(json!({ "cancelled": true }));
    };

    let export_data = accounts
        .iter()
        .map(|account| json!({ "name": account.name, "cookie": account.cookie }))
        .collect::<Vec<_>>();
    fs::write(
        &file_path,
        serde_json::to_string_pretty(&export_data).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({ "success": true, "count": accounts.len() }))
}

#[tauri::command]
fn import_accounts(state: State<'_, AppStateHandle>) -> AppResult {
    let Some(file_path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() else {
        return Ok(json!({ "cancelled": true, "imported": 0 }));
    };

    let payload = fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let imported_accounts = serde_json::from_str::<Vec<Value>>(&payload).map_err(|e| e.to_string())?;
    let mut existing_accounts = load_accounts(&state);
    let mut existing_user_ids = existing_accounts.iter().map(|account| account.user_id).collect::<Vec<_>>();
    let mut existing_cookies = existing_accounts
        .iter()
        .map(|account| account.cookie.clone())
        .collect::<Vec<_>>();

    let mut imported_count = 0_usize;
    for account in imported_accounts {
        let cookie = account
            .get("cookie")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if cookie.is_empty() || existing_cookies.contains(&cookie) {
            continue;
        }

        if let Some(user_id) = account.get("userId").and_then(|value| value.as_u64()) {
            if !existing_user_ids.contains(&user_id) {
                existing_accounts.push(StoredAccount {
                    cookie: cookie.clone(),
                    user_id,
                    name: account
                        .get("name")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    display_name: account
                        .get("displayName")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    thumbnail: account
                        .get("thumbnail")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    added_at: Utc::now().to_rfc3339(),
                });
                existing_user_ids.push(user_id);
                existing_cookies.push(cookie);
                imported_count += 1;
            }
            continue;
        }

        if let Ok(user_data) = get_roblox_user_data(&cookie) {
            if !existing_user_ids.contains(&user_data.user_id) {
                existing_user_ids.push(user_data.user_id);
                existing_cookies.push(cookie);
                existing_accounts.push(user_data);
                imported_count += 1;
            }
        }
    }

    if imported_count > 0 {
        save_accounts(&state, &existing_accounts)?;
    }

    Ok(json!({ "imported": imported_count }))
}

#[tauri::command]
fn kill_all_roblox() -> AppResult {
    let output = Command::new("pgrep")
        .arg("-x")
        .arg("RobloxPlayer")
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let count = stdout.lines().filter(|line| !line.trim().is_empty()).count();
    if count > 0 {
        let _ = Command::new("killall").arg("-9").arg("RobloxPlayer").output();
        let _ = Command::new("killall").arg("-9").arg("Roblox").output();
    }
    Ok(json!({ "count": count }))
}

#[tauri::command]
fn launch_account(state: State<'_, AppStateHandle>, user_id: u64) -> AppResult {
    let accounts = load_accounts(&state);
    let account = accounts
        .into_iter()
        .find(|entry| entry.user_id == user_id)
        .ok_or_else(|| "Account not found".to_string())?;

    let roblox_paths = [
        PathBuf::from("/Applications/Roblox.app"),
        home_dir()?.join("Applications/Roblox.app"),
    ];
    let roblox_path = roblox_paths
        .into_iter()
        .find(|path| path.exists())
        .ok_or_else(|| "Roblox not found. Please install Roblox first.".to_string())?;

    write_roblox_cookie(&account.cookie, &user_id.to_string())?;
    modify_bundle_identifier(&roblox_path, &user_id.to_string())?;

    let _ = Command::new("xattr").arg("-cr").arg(&roblox_path).output();
    let _ = Command::new("codesign")
        .arg("--force")
        .arg("--deep")
        .arg("--sign")
        .arg("-")
        .arg(&roblox_path)
        .output();

    let exec_path = roblox_path.join("Contents").join("MacOS").join("RobloxPlayer");
    let child = Command::new(&exec_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;

    let roblox_path_clone = roblox_path.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(5));
        let _ = reset_bundle_identifier(&roblox_path_clone);
    });

    Ok(json!({ "success": true, "pid": child.id() }))
}

#[tauri::command]
fn open_account_website(_user_id: u64) -> AppResult {
    Err("Opening a Roblox website session from inside the Tauri build is not supported yet.".to_string())
}

#[tauri::command]
fn open_login_window() -> AppResult {
    Ok(json!({
        "error": {
            "type": "unsupported",
            "message": "Built-in Roblox login capture is not supported in the Tauri build yet. Use Manual Add instead."
        }
    }))
}

#[tauri::command]
fn add_account_manually(state: State<'_, AppStateHandle>, cookie: String) -> AppResult {
    let warning_prefix = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_";
    let trimmed = cookie.trim();
    if trimmed.is_empty() {
        return Err("Invalid cookie provided".to_string());
    }

    let normalized_cookie = trimmed.strip_prefix(warning_prefix).unwrap_or(trimmed).trim();
    let user_data = get_roblox_user_data(normalized_cookie)
        .map_err(|_| "Invalid, expired, or banned account".to_string())?;

    let mut accounts = load_accounts(&state);
    let new_account = StoredAccount {
        cookie: normalized_cookie.to_string(),
        user_id: user_data.user_id,
        name: user_data.name,
        display_name: user_data.display_name,
        thumbnail: user_data.thumbnail,
        added_at: Utc::now().to_rfc3339(),
    };

    if let Some(existing_index) = accounts.iter().position(|entry| entry.user_id == new_account.user_id) {
        accounts[existing_index] = new_account.clone();
    } else {
        accounts.push(new_account.clone());
    }

    save_accounts(&state, &accounts)?;
    serde_json::to_value(new_account).map_err(|e| e.to_string())
}

#[tauri::command]
fn start_log_monitoring(app: AppHandle, state: State<'_, AppStateHandle>) -> AppResult {
    let log_dir = home_dir()?.join("Library").join("Logs").join("Roblox");
    if !log_dir.exists() {
        emit_to_main(
            &app,
            "updateConsoleOutput",
            Value::String(format!("Roblox logs directory not found: {}", log_dir.to_string_lossy())),
        );
        return Ok(json!({ "status": "error", "message": "Roblox logs directory not found" }));
    }

    if let Some(stop_flag) = state.inner.log_monitor_stop.lock().map_err(|e| e.to_string())?.take() {
        stop_flag.store(true, Ordering::SeqCst);
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    *state
        .inner
        .log_monitor_stop
        .lock()
        .map_err(|e| e.to_string())? = Some(stop_flag.clone());

    let app_handle = app.clone();
    let refresh_rate = state.inner.log_refresh_rate.lock().map_err(|e| e.to_string())?.to_owned();
    thread::spawn(move || {
        emit_to_main(
            &app_handle,
            "updateConsoleOutput",
            Value::String("Starting log monitoring...".to_string()),
        );

        let mut current_log_file: Option<PathBuf> = None;
        let mut file_size: u64 = 0;
        let mut last_file_check = std::time::Instant::now() - Duration::from_secs(5);

        while !stop_flag.load(Ordering::SeqCst) {
            if last_file_check.elapsed() >= Duration::from_secs(5) {
                if let Ok(entries) = fs::read_dir(&log_dir) {
                    let mut files = entries
                        .flatten()
                        .map(|entry| entry.path())
                        .filter(|path| path.is_file())
                        .collect::<Vec<_>>();
                    files.sort_by_key(|path| {
                        fs::metadata(path)
                            .and_then(|metadata| metadata.modified())
                            .ok()
                    });
                    if let Some(latest) = files.last() {
                        if current_log_file.as_ref() != Some(latest) {
                            current_log_file = Some(latest.clone());
                            file_size = fs::metadata(latest).map(|meta| meta.len()).unwrap_or(0);
                            emit_to_main(
                                &app_handle,
                                "updateConsoleOutput",
                                Value::String(format!(
                                    "Monitoring new logs from: {}",
                                    latest.file_name().and_then(|name| name.to_str()).unwrap_or("unknown")
                                )),
                            );
                        }
                    }
                }
                last_file_check = std::time::Instant::now();
            }

            if let Some(log_file) = current_log_file.as_ref() {
                if let Ok(contents) = fs::read_to_string(log_file) {
                    let bytes = contents.as_bytes();
                    if bytes.len() as u64 > file_size {
                        let new_content = &contents[file_size as usize..];
                        file_size = bytes.len() as u64;
                        let lines = new_content
                            .lines()
                            .filter(|line| !line.trim().is_empty())
                            .map(|line| {
                                let message = line
                                    .split("  ")
                                    .last()
                                    .unwrap_or(line)
                                    .trim()
                                    .to_string();
                                Value::String(format!("[Output]: {message}"))
                            })
                            .collect::<Vec<_>>();
                        if !lines.is_empty() {
                            emit_to_main(&app_handle, "batchUpdateConsole", Value::Array(lines));
                        }
                    }
                }
            }

            let sleep_millis = (refresh_rate * 1000.0).max(100.0) as u64;
            thread::sleep(Duration::from_millis(sleep_millis));
        }
    });

    Ok(json!({ "status": "success", "message": "Log monitoring started" }))
}

#[tauri::command]
fn set_log_refresh_rate(state: State<'_, AppStateHandle>, rate: f64) -> AppResult {
    let next_rate = rate.max(0.1);
    *state
        .inner
        .log_refresh_rate
        .lock()
        .map_err(|e| e.to_string())? = next_rate;
    Ok(json!({ "status": "success", "message": format!("Log refresh rate set to {next_rate}") }))
}

fn main() {
    let state = AppStateHandle::new().expect("failed to initialize JewWare paths");

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_version,
            open_scripts_folder,
            execute_script,
            execute_script_on_port,
            check_port_status,
            get_game_name,
            get_scripts,
            open_roblox,
            join_website,
            save_script,
            toggle_autoexec,
            get_local_scripts,
            delete_script,
            rename_script,
            import_script_folder,
            quit_app,
            minimize_app,
            toggle_fullscreen,
            get_latest_release_info,
            start_log_monitoring,
            set_log_refresh_rate,
            get_metadata,
            save_metadata,
            get_accounts,
            delete_account,
            export_accounts,
            import_accounts,
            kill_all_roblox,
            launch_account,
            open_account_website,
            open_login_window,
            add_account_manually
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
