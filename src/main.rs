use std::io::{self, prelude::*};
use std::os::unix::prelude::*;

use clap::Parser;
use nix::unistd;
use serde::Serialize;

/// Run a program instrumented with CMPLOG and do some stuff
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct CLI {
    /// Output file
    #[clap(short)]
    out_path: std::path::PathBuf,
    /// Path to target
    target: String,
    /// Target arguments
    args: Vec<String>,
}

fn main() -> io::Result<()> {
    let cli = CLI::parse();

    let shm_cmplog = SHM::<CmpMap>::new()?;

    let (ctl_read, ctl_write) = unistd::pipe()?;
    let (st_read, st_write) = unistd::pipe()?;

    let mut st;
    match unsafe { unistd::fork()? } {
        unistd::ForkResult::Parent { child: pid } => {
            println!("Started forkserver with PID {}", pid);
            unistd::close(ctl_read).expect("close(ctl_read)");
            unistd::close(st_write).expect("close(st_write)");
            // receive 'hello' on the status pipe
            st = io::BufReader::new(unsafe { std::fs::File::from_raw_fd(st_read) });
            let mut buf = [0; 4];
            st.read_exact(&mut buf)?;
            println!("Forkserver is up!!");
        }
        unistd::ForkResult::Child => {
            unistd::dup2(ctl_read, 198).expect("failed dup2(ctl_read, 198)");
            unistd::dup2(st_write, 199).expect("failed dup2(st_write, 199)");
            unistd::close(ctl_read).expect("close(ctl_read)");
            unistd::close(ctl_write).expect("close(ctl_write)");
            unistd::close(st_read).expect("close(st_read)");
            unistd::close(st_write).expect("close(st_write)");
            let mut cmd = std::process::Command::new(cli.target);
            cmd.args(cli.args)
                .env("AFL_DEBUG", "1")
                .env("__AFL_CMPLOG_SHM_ID", shm_cmplog.id.to_string());
            panic!("Failed to exec child: {:?}", cmd.exec());
        }
    }

    unistd::write(ctl_write, &i32::to_le_bytes(0))?;

    let mut buf = [0; 4];
    st.read_exact(&mut buf)?;
    let pid = unistd::Pid::from_raw(i32::from_le_bytes(buf));
    println!("Child has PID {}", pid);

    println!("Press enter to kill the child...");
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;

    nix::sys::signal::kill(pid, nix::sys::signal::SIGTERM)?;

    st.read_exact(&mut buf)?;
    let status = i32::from_le_bytes(buf);
    println!("Child exited with status {}", status);

    let mut stored = StoredMap { cmps: vec![] };

    for (i, x) in shm_cmplog.headers.iter().enumerate() {
        if x.val == 0 {
            continue;
        }

        let mut cmp = StoredCmp {
            header: x.val.try_into().unwrap(),
            log: vec![],
        };

        println!("{:#X?}", cmp.header);

        for (j, y) in shm_cmplog.log[i]
            .iter()
            .take(cmp.header.hits.try_into().unwrap())
            .enumerate()
        {
            if y.v0 != y.v1 {
                println!("    {:03} {:#018X} {:#018X}", j, y.v0, y.v1);
            }
            if y.v0_128 != y.v1_128 {
                println!("    {:03} {:#018X} {:#018X}   (128)", j, y.v0_128, y.v1_128);
            }
            cmp.log.push(y.clone());
        }

        stored.cmps.push(cmp);
    }

    let out_json = serde_json::to_string(&stored)?;
    std::fs::write(cli.out_path, out_json)?;

    Ok(())
}

struct SHM<T: Sized> {
    id: i32,
    ptr: *mut T,
}

impl<T> SHM<T> {
    fn new() -> io::Result<Self> {
        let id = unsafe {
            libc::shmget(
                libc::IPC_PRIVATE,
                std::mem::size_of::<T>(),
                libc::IPC_CREAT | libc::IPC_EXCL | 0o600,
            )
        };

        if id == -1 {
            return Err(io::Error::last_os_error());
        }

        let ptr = unsafe { libc::shmat(id, std::ptr::null(), 0) };
        if ptr == -1_isize as *mut libc::c_void {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            id: id as i32,
            ptr: ptr as *mut T,
        })
    }
}

impl<T> std::ops::Deref for SHM<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T> std::ops::DerefMut for SHM<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

impl<T> Drop for SHM<T> {
    fn drop(&mut self) {
        let ret = unsafe { libc::shmctl(self.id, libc::IPC_RMID, std::ptr::null_mut()) };
        if ret == -1 {
            eprintln!("shmctl failed: {}", io::Error::last_os_error());
        }
    }
}

#[derive(Debug)]
#[repr(C)]
struct CmpMap {
    headers: [CmpHeader; CMP_MAP_W],
    log: [[CmpOperands; CMP_MAP_H]; CMP_MAP_W],
}

const CMP_MAP_W: usize = 65536;
const CMP_MAP_H: usize = 32;

#[derive(Debug)]
#[repr(C)]
struct CmpHeader {
    /// unsigned hits : 24;
    /// unsigned id : 24;
    /// unsigned shape : 5;
    /// unsigned type : 2;
    /// unsigned attribute : 4;
    /// unsigned overflow : 1;
    /// unsigned reserved : 4;
    val: u64,
}

#[derive(Debug, Serialize, Clone)]
#[repr(C)]
struct CmpOperands {
    v0: u64,
    v1: u64,
    v0_128: u64,
    v1_128: u64,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct CmpHeaderUnpacked {
    hits: u32,
    id: u32,
    shape: u8,
    ty: u8,
    attribute: u8,
    overflow: bool,
}

impl std::convert::TryFrom<u64> for CmpHeaderUnpacked {
    type Error = std::num::TryFromIntError;
    fn try_from(mut x: u64) -> Result<CmpHeaderUnpacked, Self::Error> {
        let hits = (x & 0xFFFFFF).try_into()?;
        x >>= 24;
        let id = (x & 0xFFFFFF).try_into()?;
        x >>= 24;
        let shape = (x & 0x1F).try_into()?;
        x >>= 5;
        let ty = (x & 0x3).try_into()?;
        x >>= 2;
        let attribute = (x & 0xF).try_into()?;
        x >>= 4;
        let overflow = (x & 0x1) != 0;

        Ok(CmpHeaderUnpacked {
            hits,
            id,
            shape,
            ty,
            attribute,
            overflow,
        })
    }
}

#[derive(Serialize)]
struct StoredMap {
    cmps: Vec<StoredCmp>,
}

#[derive(Serialize)]
struct StoredCmp {
    header: CmpHeaderUnpacked,
    log: Vec<CmpOperands>,
}
