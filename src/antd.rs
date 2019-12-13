
extern crate libc;
pub use std::ffi::c_void;
use std::os::raw::c_char;
use std::ffi::CStr;
use std::ffi::CString;
use std::collections::HashMap;
use std::fmt::{Arguments,Write};

const DHASHSIZE: usize = 50;

static mut __PLUGIN__: PluginHeader = PluginHeader{
    name: std::ptr::null(),
    dbpath: std::ptr::null(),
    htdocs: std::ptr::null(),
    pdir: std::ptr::null(),
    sport: 0,
    raw_body: 0,
    usessl: 0
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
    htdocs: * const c_char,
    pdir: *const c_char,
	sport: u32,
    raw_body: u32,
    usessl: u32
}


#[repr(C)]
pub struct Config
{
    port: u32,
    plugins_dir: *const c_char,
    plugins_ext: *const c_char,
    db_path: *const c_char,
    htdocs: *const c_char,
    tmpdir: *const c_char,
    rules: *const c_void,
    handlers: *const c_void,
    backlog: u32,
    maxcon: u32,
    connection: u32,
    n_workers: u32,
    errorfp: *const c_void,
    logfp: * const c_void,
    usessl: u32,
    sslcert: *const c_char,
    sslkey:* const c_char
}


#[repr(C)]
pub struct Client
{
    sock: u32,
    ssl: *const c_void,
    ip: *const c_char,
    status: u32,
    last_io: libc::time_t
}

impl Client {
    pub fn print(&self)
    {
        if let Ok(s) = cstr!(self.ip)
        {
            print!("sock {}, ip: {}\n", self.sock, s);
        }
    }
}

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
type Dictionary = *const PairList;


#[repr(C)]
pub struct Request
{
    client: *const Client,
    data: Dictionary
}

impl<'a> Request {

    pub fn from(rq:*const Request) -> &'a Request
    {
        unsafe
        {
            &*rq
        }
    }

    pub fn get_data(&self) -> RequestData
    {
        RequestData::from(&self)
    }

    pub fn get_client(&self) -> &'a Client
    {
        unsafe
        {
            &*self.client
        }
    }
}

pub struct RequestData<'a>
{
    cookie: HashMap<&'a str, &'a str>,
    header: HashMap<&'a str, &'a str>,
    data: HashMap<&'a str, &'a str>
}

pub unsafe fn dict_to_map(dict:Dictionary, map: &mut HashMap<&str, &str>)
{
    if dict != std::ptr::null()
    {
        for i in 0..DHASHSIZE {
            let list: PairList = *(dict.offset(i as isize));
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
            if request.data != std::ptr::null()
            {
                for i in 0..DHASHSIZE {
                    let list: PairList = *(request.data.offset(i as isize));
                    if list != std::ptr::null()
                    {
                        let mut handle = |k,v|
                        {
                            if let Ok(ks) = cstr!(k)
                            {
                                let _ = match ks {
                                    "COOKIE" => dict_to_map(v as Dictionary, & mut cookie),
                                    "REQUEST_HEADER" => dict_to_map(v as Dictionary, & mut header),
                                    "REQUEST_DATA" =>  dict_to_map(v as Dictionary, & mut data),
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

pub struct Task
{
    ptr: *const c_void
}

#[link(name="antd")]
extern {
    fn antd_create_task(
        handle: *const fn(*const c_void) -> c_void, 
        data: *const c_void,
        callback:*const fn(*const c_void) -> c_void,
        time: libc::time_t
    ) -> *const c_void;
    fn server_log(fmt: *const c_char, msg:*const c_char) -> ();
    fn error_log(fmt: *const c_char, msg:*const c_char) -> ();
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
        let prefix = format!("[{}:{}]: ", file!(), line!());
        log(&prefix[..], false, format_args!($($args)*));
    })
}


#[macro_export]
macro_rules! ERROR {
    ($($args:tt)*) => ({ 
        let prefix = format!("[{}:{}]: ", file!(), line!());
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
    pub fn from( handle: *const fn(*const Request) -> (),data: *const Request, callback:*const fn(*const Request) -> (), time: libc::time_t) -> Task
    {
        unsafe{
            Task
            {
                ptr: antd_create_task(handle as *const fn(*const c_void)-> c_void, data as *const c_void, callback as *const fn(*const c_void)-> c_void, time)
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
        __PLUGIN__.htdocs = (*config).htdocs;
        __PLUGIN__.pdir = (*config).plugins_dir;
        __PLUGIN__.sport = (*config).port;
        __PLUGIN__.raw_body = 0;
        __PLUGIN__.usessl = (*config).usessl;
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

pub fn htdocs<'a>() -> Option<&'a str>
{
    if let Ok(name) = cstr!(__PLUGIN__.htdocs)
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

pub fn port<'a>() -> u32
{
    unsafe
    {
        __PLUGIN__.sport
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

}

#[no_mangle]
pub unsafe extern fn __release__()
{
    if __PLUGIN__.name != std::ptr::null()
    {
        libc::free(__PLUGIN__.name as *mut c_void);
    }
    
}