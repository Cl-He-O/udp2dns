use clap::Parser;
use log::{info, warn};
use std::{
    cmp::min,
    io::Result,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
};
use trust_dns_proto::{
    op::{Message, Query},
    rr::{rdata::TXT, Name, RData, Record, RecordType},
};

#[derive(Parser)]
struct Config {
    listen: String,
    dst: String,
    #[arg(long)]
    client: bool,
    #[arg(long)]
    loglevel: Option<String>,
}

fn main() -> Result<()> {
    let config = Config::parse();

    env_logger::builder()
        .parse_filters(&config.loglevel.unwrap_or("warn".to_string()))
        .init();

    let listen = config.listen.to_socket_addrs()?.next().unwrap();
    let dst = config.dst.to_socket_addrs()?.next().unwrap();

    let usock = UdpSocket::bind(listen)?;

    warn!("listening on {}", usock.local_addr()?);

    if config.client {
        client(usock, dst)
    } else {
        server(usock, dst)
    }
}

const NAME_L: usize = 63;

fn client(usock: UdpSocket, dst: SocketAddr) -> Result<()> {
    let mut buf = vec![0_u8; 0x1000];
    let mut src = None;

    loop {
        let (received, from) = usock.recv_from(&mut buf)?;

        info!("{} bytes received from {}", received, from);

        if from == dst {
            if let Some(to) = src {
                match Message::from_vec(&buf[..received]) {
                    Ok(msg) => {
                        let mut s = String::new();

                        msg.answers().iter().for_each(|rec| {
                            s += &rec.data().unwrap().as_txt().unwrap().to_string();
                        });
                        match base64::decode_config(s, base64::URL_SAFE_NO_PAD) {
                            Ok(b) => {
                                info!("forwarding to {}", to);
                                usock.send_to(&b, to)?;
                            }
                            Err(err) => {
                                warn!("{}", err);
                            }
                        }
                    }
                    Err(err) => {
                        warn!("{}", err);
                    }
                };
            } else {
                warn!("ignored (cannot determine destination)");
            }
        } else {
            src = Some(from);
            info!("forwarding to {}", dst);

            let s = base64::encode_config(&buf[..received], base64::URL_SAFE_NO_PAD);
            let s = s.as_bytes();

            let mut msg = Message::new();

            msg.set_id(rand::random())
                .add_queries((0..s.len()).step_by(NAME_L).map(|i| {
                    let mut q = Query::new();
                    q.set_name(Name::from_labels(vec![&s[i..min(i + NAME_L, s.len())]]).unwrap());
                    q
                }));

            usock.send_to(&msg.to_vec().unwrap(), dst)?;
        }
    }
}

const TXT_L: usize = 255;

fn server(usock: UdpSocket, dst: SocketAddr) -> Result<()> {
    let mut buf = vec![0_u8; 0x1000];
    let mut src = None;

    let mut q_id = vec![];

    loop {
        let (received, from) = usock.recv_from(&mut buf)?;

        info!("{} bytes received from {}", received, from);

        if from == dst {
            if let Some(to) = src {
                let s = base64::encode_config(&buf[..received], base64::URL_SAFE_NO_PAD);

                let mut msg = Message::new();
                msg.set_id(if q_id.len() < 50 {
                    rand::random()
                } else {
                    q_id.pop().unwrap()
                })
                .add_answers((0..s.len()).step_by(TXT_L).map(|i| {
                    let mut r = Record::new();
                    r.set_record_type(RecordType::TXT)
                        .set_data(Some(RData::TXT(TXT::new(vec![String::from(
                            &s[i..min(i + TXT_L, s.len())],
                        )]))));
                    r
                }));

                info!("forwarding to {}", to);

                usock.send_to(&msg.to_vec().unwrap(), to)?;
            } else {
                warn!("ignored (cannot determine destination)");
            }
        } else {
            src = Some(from);

            match Message::from_vec(&buf[..received]) {
                Ok(msg) => {
                    let mut s = String::new();

                    msg.queries().iter().for_each(|q| {
                        s += q.name().to_string().trim_end_matches('.');
                    });

                    match base64::decode_config(s, base64::URL_SAFE_NO_PAD) {
                        Ok(s) => {
                            info!("forwarding to {}", dst);

                            if q_id.len() < 500 {
                                q_id.push(msg.id());
                            }

                            usock.send_to(&s, dst)?;
                        }
                        Err(err) => {
                            warn!("{}", err);
                        }
                    }
                }
                Err(err) => {
                    warn!("{}", err);
                }
            }
        }
    }
}
