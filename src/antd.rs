
extern crate libc;
use std::io::prelude::*;
pub use std::ffi::c_void;
use std::os::raw::c_char;
use std::ffi::CStr;
use std::ffi::CString;
use std::collections::HashMap;
use std::fmt::{Arguments,Write};
use std::fs::File;
use std::io::BufReader;

const MAX_BUF_SIZE: usize = 1024;

static mut __PLUGIN__: PluginHeader = PluginHeader{
    name: std::ptr::null(),
    dbpath: std::ptr::null(),
    tmpdir: std::ptr::null(),
    pdir: std::ptr::null(),
    raw_body: 0
};

macro_rules! cstr {
    ($ptr:expr) => {
        unsafe {
            CStr::from_ptr($ptr).to_str()
        }
    }
}


#[repr(C)]
pub struct PluginHeader
{
    name: *const c_char,
    dbpath: *const c_char,
    tmpdir: * const c_char,
    pdir: *const c_char,
    raw_body: u32
}


#[repr(C)]
pub struct PortConfig
{
    port: u32,
    usessl: i32,
    htdocs: *const c_char,
    sock: i32,
    rules: *const c_void
}

#[repr(C)]
pub struct Config
{
    plugins_dir: *const c_char,
    plugins_ext: *const c_char,
    db_path: *const c_char,
    tmpdir: *const c_char,
    handlers: *const c_void,
    backlog: u32,
    maxcon: u32,
    connection: u32,
    n_workers: u32,
    errorfp: *const c_void,
    logfp: * const c_void,
    enable_ssl: u32,
    sslcert: *const c_char,
    sslkey:* const c_char,
    ssl_cipher: *const c_char,
    mimes: *const Dictionary,
    ports: *const Dictionary
}


#[repr(C)]
pub struct Client
{
    sock: u32,
    ssl: *const c_void,
    ip: *const c_char,
    status: u32,
    last_io: libc::time_t,
    port_config: *const PortConfig
}

//impl Client {
//}

//#[derive(Copy, Clone)]
#[repr(C)]
pub struct Pair
{
    next: *const Pair,
    pub key: *const c_char,
    pub value: * const c_void
}

impl Pair {
    pub fn each(&self, dof:&mut impl FnMut(*const c_char, *const c_void))
    {
        unsafe{
            dof(self.key, self.value);
            if (self.next as *const c_void) != std::ptr::null()
            {
                (*self.next).each(dof);
            }
        }
    }
}

type PairList = *const Pair;
#[repr(C)]
pub struct Dictionary
{
    cap: u32,
    map: *const PairList,
    size: u32
}


#[repr(C)]
pub struct Request
{
    client: *const Client,
    data: *const Dictionary
}

pub enum WSStatus{
    OK,
    CLOSED,
    ERR,
    NOT_WS
}

impl Request {

    pub fn get_data(&self) -> RequestData
    {
        RequestData::from(&self)
    }
    pub fn set_state(&self, state: &str) -> bool
    {
        unsafe{
            if let Ok(key) = CString::new("__RUST__STATE__")
            {
                if let Ok(value) = CString::new(state)
                {
                    let _ = dput(self.data, key.as_ptr() as *const c_char, libc::strdup(value.as_ptr() as *const c_char));
                    return true;
                }
            }
            
            false
        }
    }
    pub fn get_state(&self) -> Option<String>
    {
        let data = self.get_data();
        match data.header.get("__RUST__STATE__")
        {
            Some(s) => Some(String::from(*s)),
            None => None
        }
    }
    fn get_client(&self) -> *const Client
    {
       self.client
    }
    pub fn port(&self) -> u32
    {
        unsafe
        {
            (*(*self.client).port_config).port
        }
    }
    pub  fn htdocs(&self) ->Option<&str>
    {
        unsafe
        {
            if let Ok(s) = cstr!((*(*self.client).port_config).htdocs)
            {
                Some(s)
            }
            else
            {
                None
            }
        }
   }
   pub fn is_websocket(&self) -> bool
   {
        let data = self.get_data();
        let header = data.get_header();
        match header.get("__web_socket__")
        {
            Some(s) => true,
            None => false
        }
   }
    pub fn read(&self, buf:&[u8]) -> Result<i32,i32>
    {
        unsafe
        {
            let ret = antd_recv(self.client as *const c_void, buf.as_ptr() as *const c_void, buf.len() as u32);
            if ret >= 0
            {
                Ok(ret)
            }
            else
            {
                Err(ret)
            }
        }
    }
    /// This function is used only for web socket
    ///
    /// It read one frame data
    pub fn wsread(&self, handle: &Fn(&[u8], bool)) -> WSStatus
    {
        unsafe{
            if self.is_websocket()
            {
                let mut buf:Vec<u8> = vec![0; MAX_BUF_SIZE];
                let header = ws_read_header(self.client);
                if header != std::ptr::null()
                {
                    if (*header).mask == 0
                    {
                        libc::free(header as *mut c_void);
                        ws_send_close(self.client,1011,0);
                        return WSStatus::CLOSED;
                    }
                    // close opcode
                    if (*header).opcode == 0x8
                    {
                        libc::free(header as *mut c_void);
                        ws_send_close(self.client,1011,0);
                        return WSStatus::CLOSED;
                    }
                    if (*header).opcode == 0x01 || (*header).opcode == 0x02
                    {
                        let bin = if (*header).opcode == 0x02 {true} else {false};
                        
                        loop
                        {
                            let n = ws_read_data(self.client, header, buf.len() as i32, buf.as_mut_ptr() as *const u8);
                            if n == -1 
                            {
                                libc::free(header as *mut c_void);
                                return return WSStatus::ERR;
                            }
                            if n == 0
                            {
                                libc::free(header as *mut c_void);
                                return WSStatus::OK;
                            }
                            buf.truncate(n as usize);
                            handle(&buf,bin);
                            buf.resize(MAX_BUF_SIZE,0);
                        }
                    }
                    else
                    {
                        libc::free(header as *mut c_void);
                        ws_send_close(self.client,1011,0);
                        return WSStatus::ERR;
                    }
                }
                else
                {
                    WSStatus::ERR
                }
            }
            else
            {
                WSStatus::NOT_WS
            }
        }
    }
}

#[repr(C)]
pub struct WSHeader
{
    fin: u8,
    opcode: u8,
    plen: u32,
    mask: u8,
    mask_key: [u8;4]
}


#[repr(C)]
pub struct Response
{
    cookie: Vec<String>,
    header: HashMap<String, String>,
    client: *const Client,
    status: i32,
    hflag:bool,
    ws: bool
}

impl Response{
    fn from(client:*const Client) -> Response
    {
        let mut header = HashMap::new();
        header.insert(String::from("Server"),String::from("Antd"));
        Response {
            cookie:Vec::new(),
            header: header,
            client:client,
            status: 200,
            hflag: false,
            ws: false
        }
    }

    pub fn set_status(&mut self, v:i32) 
    {
        self.status = v;
    }

    pub fn set_ws(&mut self, v:bool)
    {
        self.ws = v;
    }

    pub fn set_header(&mut self, k: & str, v: & str)
    {
        self.header.insert(String::from(k),String::from(v));
    }

    pub fn set_cookie(&mut self,v:& str)
    {
        self.cookie.push(String::from(v));
    }

    fn set_flag(&mut self, v: bool)
    {
        self.hflag = v;
    }

    pub fn send_header(&self) -> Result <i32,String>
    {
        let mut buf: String;
        if let Ok(s) = cstr!(get_status_str(self.status))
        {
            buf = format!("HTTP/1.1 {} {}\r\n", self.status, s);
        }
        else
        {
            buf = format!("HTTP/1.1 {} {}\r\n", self.status, "Unofficial Status");
        }
        self.send(buf.as_bytes())?;
        // write header
        for (k,v) in self.header.iter()
        {
            buf = format!("{}: {}\r\n",k, v);
            self.send(buf.as_bytes())?;
        }
        // write cookie
        for v in self.cookie.iter()
        {
            buf = format!("Set-Cookie: {}\r\n",v);
            self.send(buf.as_bytes())?;
        }
        // write end
        self.send(b"\r\n\r\n" as &[u8])?;
        Ok(1)
    }
    pub fn write(&mut self, buf:&[u8], bin: bool) -> Result<i32,String>
    {
        if self.ws
        {
            unsafe{
                if bin
                {
                    ws_send_text(self.client, buf.as_ptr() as *const c_char,0);
                    Ok(buf.len() as i32)
                }
                else
                {
                    ws_send_binary(self.client, buf.as_ptr(), buf.len() as i32,0);
                    Ok(buf.len() as i32)
                }
            }
        }
        else
        {
            if !self.hflag 
            {
                self.send_header()?;
                self.set_flag(true);
            }
            self.send(buf)
        }
    }
    pub fn send(&self, buf:&[u8]) -> Result<i32,String>
    {
        unsafe
        {
            let ret = antd_send(self.client as *const c_void, buf.as_ptr() as *const c_void, buf.len() as u32);
            if ret >= 0
            {
                Ok(ret)
            }
            else
            {
                Err(format!("Error when write out data: {}",ret))
            }
        }
    }
}


pub fn read_config(file: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(f) = File::open(file) {
        let buf = BufReader::new(f);
        for result in buf.lines() {
            if let Ok(line) = result {
                let str = line.trim();
                if let Some(ch) = str.chars().next() {
                    if ch != '#' {
                        if let Some(i) = str.find('=') {
                            map.insert(
                                String::from(str[..i - 1].trim()),
                                String::from(str[i + 1..].trim()),
                            );
                        }
                    }
                }
            }
        }
    }
    map
}

pub struct RequestData<'a>
{
    cookie: HashMap<&'a str, &'a str>,
    header: HashMap<&'a str, &'a str>,
    data: HashMap<&'a str, &'a str>
}

pub unsafe fn dict_to_map(dict:*const Dictionary, map: &mut HashMap<&str, &str>)
{
    if (*dict).map != std::ptr::null()
    {
        for i in 0..(*dict).cap {
            let list: PairList = *((*dict).map.offset(i as isize));
            if list != std::ptr::null()
            {
                let mut handle = |k,v|
                {
                    if let Ok(ks) = cstr!(k)
                    {
                        if let Ok(vs) = cstr!(v as *const c_char)
                        {
                            map.insert(ks, vs);
                        }
                    }
                };
                (*list).each(&mut handle);
            }
        }
    }
}

impl<'a> RequestData<'a> {
    pub fn from(request: &Request) -> RequestData
    {
        unsafe{
            let mut data:HashMap<&str, &str> = HashMap::new();
            let mut cookie:HashMap<&str, &str> = HashMap::new();
            let mut header:HashMap<&str, &str> = HashMap::new();
            if (*request.data).map != std::ptr::null()
            {
                for i in 0..(*request.data).cap {
                    let list: PairList = *((*request.data).map.offset(i as isize));
                    if list != std::ptr::null()
                    {
                        let mut handle = |k,v|
                        {
                            if let Ok(ks) = cstr!(k)
                            {
                                let _ = match ks {
                                    "COOKIE" => dict_to_map(v as *const Dictionary, & mut cookie),
                                    "REQUEST_HEADER" => dict_to_map(v as *const Dictionary, & mut header),
                                    "REQUEST_DATA" =>  dict_to_map(v as *const Dictionary, & mut data),
                                    _ => {
                                        if let Ok(vs) = cstr!(v as *const c_char)
                                        {
                                            header.insert(ks, vs);
                                        }
                                    }
                                };
                            }
                        };
                        (*list).each(&mut handle);
                    }
                }
            }
            RequestData{
                cookie,header,data
            }
        }
    }

    pub fn get_cookie(&self) -> &HashMap<&'a str, &'a str>
    {
        & self.cookie
    }

    pub fn get_header(&self) -> &HashMap<&'a str, &'a str>
    {
        & self.header
    }

    pub fn get_data(&self) -> &HashMap<&'a str, &'a str>
    {
        & self.data
    }
}

#[repr(C)]
pub struct Task
{
    ptr: *const c_void
}

#[link(name="antd")]
extern {
    fn antd_create_task(
        handle: *const fn(*const c_void) -> *const c_void, 
        data: *const c_void,
        callback:*const fn(*const c_void) -> *const c_void,
        time: libc::time_t
    ) -> *const c_void;
    fn server_log(fmt: *const c_char, msg:*const c_char) -> ();
    fn dput(dic:*const Dictionary, k: *const c_char, v: *const c_char) -> *const c_void;
    fn error_log(fmt: *const c_char, msg:*const c_char) -> ();
    fn antd_send(source: *const c_void, data: *const c_void, len: u32) -> i32;
    fn antd_recv(source: *const c_void,  data: *const c_void, len: u32) -> i32;
    fn init() -> ();
    fn process(request: &Request, response: &mut Response) -> Task;
    fn antd_error(client:*const c_void, stat: i32, msg: *const c_char) -> ();
    fn get_status_str(stat: i32) -> *const c_char;
    // websocket
    fn ws_read_header(client:*const Client) -> *const WSHeader;
    fn ws_send_text(client: *const Client, data: *const c_char,mask: i32) -> ();
    fn ws_send_file(client: *const Client, data: *const c_char,mask: i32) -> ();
    fn ws_send_binary(client:*const Client, data: *const u8, size: i32,mask:i32)->();
    fn ws_send_close(client:*const Client, stat:u32,mask:i32)->();
    fn ws_read_data(client:*const Client, header:*const WSHeader, size:i32, data:*const u8) -> i32;
    fn server_time() -> *const c_char;
}

#[no_mangle]
pub unsafe extern fn handle(ptr: *const Request) -> *const c_void
{
    let request = &*ptr;
    let mut response = Response::from(request.get_client());
    if request.is_websocket()
    {
        response.set_ws(true);
    }
    let task = process(&request, &mut response);
    task.get_ptr()
}


pub fn log(prefix:&str, error:bool, args: Arguments<'_>)  {
    let mut output = String::new();
    unsafe{
        if let Ok(_) = output.write_fmt(args)
        {
            let log_fmt = format!("{}%s\n", prefix);
            if let Ok(fmt) = CString::new(log_fmt.as_bytes())
            {
                if let Ok(c_msg) = CString::new(output.as_bytes())
                {
                    if error
                    {
                        error_log(fmt.as_ptr(), c_msg.as_ptr());
                    }
                    else
                    {
                        server_log(fmt.as_ptr(), c_msg.as_ptr());
                    }
                }
            }
        }
    }
}

#[macro_export]
macro_rules! LOG {
    ($($args:tt)*) => ({
        let prefix = format!("{}: [{}:{}]: ", server_time_str(), file!(), line!());
        log(&prefix[..], false, format_args!($($args)*));
    })
}


#[macro_export]
macro_rules! ERROR {
    ($($args:tt)*) => ({ 
        let prefix = format!("{}: [{}:{}]: ", server_time_str(), file!(), line!());
        log(&prefix[..], true, format_args!($($args)*));
    })
}

impl Task {
    pub fn empty(rq: *const Request) -> Task
    {
        let mut t: libc::time_t = 0;
        unsafe{
            Task::from(std::ptr::null(), rq, std::ptr::null(),libc::time(&mut t))
        }
    }
    pub fn again(rq: *const Request) -> Task
    {
        let mut t: libc::time_t = 0;
        unsafe{
            Task::from(handle as *const fn(*const Request)-> *const c_void, rq, std::ptr::null(),libc::time(&mut t))
        }
    }
    pub fn from( handle: *const fn(*const Request) -> *const c_void,data: *const Request, callback:*const fn(*const Request) -> *const c_void, time: libc::time_t) -> Task
    {
        unsafe{
            Task
            {
                ptr: antd_create_task(handle as *const fn(*const c_void)->*const c_void, data as *const c_void, callback as *const fn(*const c_void)-> *const c_void, time)
            }
        }
    }
    pub fn get_ptr(&self) -> *const c_void
    {
        self.ptr
    }
}

fn __(name: *const c_char, config: *const Config)
{
    unsafe{
        __PLUGIN__.name = libc::strdup(name);
        __PLUGIN__.dbpath = (*config).db_path;
        __PLUGIN__.tmpdir = (*config).tmpdir;
        __PLUGIN__.pdir = (*config).plugins_dir;
        __PLUGIN__.raw_body = 0;
    }
}

pub fn use_raw_body(value: bool)
{
    unsafe{
        __PLUGIN__.raw_body = if value {1} else {0};
    }
}

#[no_mangle]
pub extern  fn meta() -> *const PluginHeader
{
    unsafe{
        &__PLUGIN__
    }
}

pub fn tmpdir<'a>() -> Option<&'a str>
{
    if let Ok(name) = cstr!(__PLUGIN__.tmpdir)
    {
        Some(name)
    }
    else
    {
        None
    }
}

pub fn plugin_name<'a>() -> Option<&'a str>
{
    if let Ok(name) = cstr!(__PLUGIN__.name)
    {
        Some(name)
    }
    else
    {
        None
    }
}

pub fn plugin_root<'a>() -> Option<&'a str>
{
    if let Ok(name) = cstr!(__PLUGIN__.pdir)
    {
        Some(name)
    }
    else
    {
        None
    }
}

pub fn db_root<'a>() -> Option<&'a str>
{
    if let Ok(name) = cstr!(__PLUGIN__.dbpath)
    {
        Some(name)
    }
    else
    {
        None
    }
}

pub fn server_time_str() -> String
{
    if let Ok(s) = cstr!(server_time())
    {
        String::from(s)
    }
    else
    {
        String::new()
    }
}

pub fn is_raw<'a>() -> bool
{
    unsafe{
        if __PLUGIN__.raw_body == 0 {
            false
        }
        else
        {
            true
        }
    }
}

#[no_mangle]
pub extern  fn __init_plugin__(ptr:*const c_char, config: *const Config)
{
    __(ptr, config);
    unsafe{
        init();
    }
}

#[no_mangle]
pub unsafe extern fn __release__()
{
    if __PLUGIN__.name != std::ptr::null()
    {
        libc::free(__PLUGIN__.name as *mut c_void);
    }
    
}
