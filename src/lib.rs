
//! This library defines an antd plugin interface wrapper in RUST
//! and expose all libantd utilities functions
pub mod antd;
pub use antd::*;

#[no_mangle]
pub extern fn handle(ptr: *const antd::Request) -> *const c_void
{
    print!("name: {}\n",antd::plugin_name().unwrap());
    print!("port: {}\n",antd::port());
    print!("www : {}\n",antd::htdocs().unwrap());
    print!("DB  : {}\n",antd::db_root().unwrap());
    print!("TMP : {}\n",antd::plugin_root().unwrap());
    print!("raw?: {}\n",antd::is_raw());
    let request = Request::from(ptr);
    LOG!("Log to log file");
    ERROR!("Error found {}, to error file", 10);
    let client = request.get_client();
    client.print();
    let request_data = request.get_data();
    let header = request_data.get_header();
    let data = request_data.get_data();
    let cookie = request_data.get_cookie();
    for (k,v) in header.iter()
    {
        print!("[HEADER] {}:{}\n", k, v);
    }

    for (k,v) in data.iter()
    {
        print!("[DATA] {}:{}\n", k, v);
    }

    for (k,v) in cookie.iter()
    {
        print!("[COKKIE] {}:{}\n", k, v);
    }
    let task = Task::empty(request);
    task.get_ptr()
}