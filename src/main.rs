use hex_slice::AsHex;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::io::Write;

use core::fmt;

use bytes::Bytes;

use tokio::runtime::Runtime;
use tokio::time::{delay_for, Duration};

#[macro_use]
extern crate bitflags;

use libc::c_ulong;
use tokio::task;
use serialport::{FlowControl, Parity, DataBits, StopBits, SerialPort};
use std::io::Read;
use std::thread::sleep;

// constants stolen from C libs
const TIOCSRS485: c_ulong = 0x542f;

// bitflags used by rs485 functionality
bitflags! {
    pub struct Rs485Flags: u32 {
        const SER_RS485_ENABLED        = (1 << 0);
        const SER_RS485_RTS_ON_SEND    = (1 << 1);
        const SER_RS485_RTS_AFTER_SEND = (1 << 2);
        const SER_RS485_RX_DURING_TX   = (1 << 4);
    }
}

impl fmt::Display for Rs485Flags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.bits)
    }
}

pub struct SerialRs485 {
    pub flags: Rs485Flags,
    pub delay_rts_before_send: u32,
    pub delay_rts_after_send: u32,
    pub _padding: [u32; 5],
}

static mut ERRORS: u32 = 0;
static mut REQS: u32 = 0;
static mut TIMEOUTS: u32 = 0;

/// Modbus RTU response frame min. size
const MB_RTU_MIN_RESPONSE_LEN: usize = 5;

fn check_crc(serial_data: &Bytes) -> bool
{
    use crc16::*;
    use byteorder::{ByteOrder, LittleEndian};
    if serial_data.len() < MB_RTU_MIN_RESPONSE_LEN
    {
        return false;
    }
    let frame_without_crc = &serial_data[0..serial_data.len()-2];
    let crc : u16 = LittleEndian::read_u16(&serial_data[serial_data.len()-2..serial_data.len()]);
    return crc == State::<MODBUS>::calculate(frame_without_crc);
}

fn set_rs485_mode(fd: RawFd)
{
    println!("fd : {}", fd);

    let pad = [0u32; 5];
    let mut flags = Rs485Flags::SER_RS485_ENABLED;

    /* If sending HI LEVEL */
    flags &= !(Rs485Flags::SER_RS485_RTS_ON_SEND);

    /* If recv LO LEVEL */
    flags |= Rs485Flags::SER_RS485_RTS_AFTER_SEND;

    flags |= Rs485Flags::SER_RS485_RX_DURING_TX;

    println!("rs485 flags: {:?}", flags);
    println!("rs485 flags: {}", flags) ;

    let mut rs485ctl  = SerialRs485{flags, delay_rts_before_send: 0,  delay_rts_after_send: 0, _padding: pad};

    let rval = unsafe { libc::ioctl(fd, TIOCSRS485, &mut rs485ctl as *mut SerialRs485) };
    if rval == -1 {
        println!("rs485 ioctl error");
        std::process::exit(1);
    }
}

async fn process()
{
    let port_name = "/dev/ttyO4";

    let s = serialport::new(port_name, 115200)
        .flow_control(FlowControl::None)
        .data_bits(DataBits::Eight)
        .stop_bits( StopBits::One)
        .parity(Parity::None)
        .timeout(Duration::from_millis(1000));

    let mut port = s.open_native().unwrap();
    port.set_exclusive(true).unwrap();

    let fd = port.as_raw_fd();
    set_rs485_mode(fd);

    println!("Timeout: {:?}", port.timeout());
    delay_for(Duration::from_millis(1000)).await;

    let port_mutex = Arc::new(Mutex::new(port));

    let mb_request: Vec<u8> = vec![0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD];

    let req_regs_cnt = mb_request[5];
    let response_bytes_cnt = ((req_regs_cnt*2) + 5) as usize;

    loop
    {
        let req = mb_request.clone();
        let port_mutex_cloned = port_mutex.clone();
        {
            task::spawn_blocking(move || {
                let old = chrono::Local::now();

                let mut port = port_mutex_cloned.lock().unwrap();
                match port.write(&req.as_slice())
                {
                    Ok(_size) => {
                        unsafe {
                            REQS = REQS + 1;
                            println!("Write bytes : {:02X}, Reqs: {}", req.as_hex(), REQS);
                        }
                    },
                    Err(e) => { println!("Error. Failed write. Error: {}", e); }
                };

                let mut buf = vec![0; response_bytes_cnt as usize];
                sleep(Duration::from_micros(300));

                match port.read_exact(&mut buf)
                {
                    Ok(()) => {
                        let serial_data_vec = buf.to_vec();
                        let res = check_crc(&Bytes::from(serial_data_vec.clone()));

                        unsafe {
                            if !res
                            {
                                ERRORS = ERRORS + 1;
                                println!("CRC ERROR!");
                            }
                            println!("Readed bytes : {:02X} Errors: {}, Timeouts: {}",  serial_data_vec.as_hex(), ERRORS, TIMEOUTS);
                        }
                    },
                    Err(e) => {
                        unsafe {
                            if e.kind() == std::io::ErrorKind::TimedOut { TIMEOUTS = TIMEOUTS + 1; }
                            else { ERRORS = ERRORS + 1; }
                            println!("Error. Failed read. Error : {}, Errors: {}, Timeouts: {}", e, ERRORS, TIMEOUTS);
                        }
                    },
                };

                sleep(Duration::from_micros(300));
                println!("Period: {} ms", (chrono::Local::now()-old).num_milliseconds());

            }).await.unwrap();

        }
    }
}

fn main() {
    println!("RS 485 Example");

    let mut rt = Runtime::new().expect("Tokio runtime error");

    rt.block_on(async move {
        println!("Tokio Runtime ok");
        process().await;
    });
}

