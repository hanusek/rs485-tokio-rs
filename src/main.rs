use hex_slice::AsHex;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use core::fmt;

use bytes::Bytes;

use tokio_serial::*;
use tokio::runtime::Runtime;
use tokio::time::{delay_for, Duration};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::sync::Mutex;

#[macro_use]
extern crate bitflags;

use libc::c_ulong;

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
    let mut settings = tokio_serial::SerialPortSettings::default();
    settings.baud_rate = 115200;
    settings.flow_control = FlowControl::None;
    settings.parity = Parity::None;
    settings.data_bits = DataBits::Eight;
    settings.stop_bits = StopBits::One;
    settings.timeout = Duration::from_millis(1000);

    let port_name = "/dev/ttyO4";

    let mut port = Serial::from_path(port_name, &settings).unwrap();
    let fd = port.as_raw_fd();
    set_rs485_mode(fd);

    port.set_exclusive(true).unwrap();

    let port_mutex  = Arc::new(Mutex::new(port));

    loop
    {
        let old = chrono::Local::now();

        let mut serial_data = [0 as u8; 255];

        let mb_request: Vec<u8> = vec![0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD];

        let mut spt = port_mutex.lock().await;
        {
            let r = spt.write(mb_request.as_slice()).await;
            match r
            {
                Ok(_size) => {
                    unsafe {
                        REQS = REQS + 1;
                        println!("Write bytes : {:02X}, Reqs: {}", mb_request.as_hex(), REQS);
                    }
                },
                Err(e) => {
                    println!("Error. Failed write. Error: {}", e);
                }
            }

            delay_for(Duration::from_millis(1)).await;

            let r = spt.read(&mut serial_data).await;
            match r
            {
                Ok(size) => {
                    if size == 0 { return; }
                    unsafe {
                        let serial_data_vec = serial_data[..size].to_vec();
                        if !check_crc(&Bytes::from(serial_data_vec.clone()))
                        {
                            ERRORS = ERRORS + 1;
                            println!("CRC ERROR!");
                        }
                        println!("Readed bytes : {:02X} Errors: {}, Timeouts: {}", serial_data[..size].as_hex(), ERRORS, TIMEOUTS);
                    }
                },
                Err(e) => {
                    unsafe {
                        if e.kind() == std::io::ErrorKind::TimedOut
                        {
                            TIMEOUTS = TIMEOUTS + 1;
                        } else {
                            ERRORS = ERRORS + 1;
                        }
                        println!("Error. Failed read. Error : {}, Errors: {}, Timeouts: {}", e, ERRORS, TIMEOUTS);
                    }
                },
            };

            delay_for(Duration::from_millis(5)).await;

            let new = chrono::Local::now();
            let dur = new - old;
            println!("Period : {} us", dur.num_microseconds().unwrap());
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

