use clap::Parser;
use log::{info, warn};
use std::{
    cmp::min,
    collections::HashMap,
    io::Result,
    net::{SocketAddr, ToSocketAddrs},
};

use tokio::net::UdpSocket;

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

const BUF_SIZE: usize = 0x1000;
const NAME_L: usize = 63;
const TXT_L: usize = 255;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    env_logger::builder()
        .parse_filters(&config.loglevel.unwrap_or("warn".to_string()))
        .init();

    let dst = config.dst.to_socket_addrs().unwrap().next().unwrap();

    let usock = UdpSocket::bind(config.listen).await?;

    warn!("listening on {}", usock.local_addr()?);

    let mut buf = vec![0_u8; BUF_SIZE];

    let (mut table_send, mut table_recv) = (HashMap::new(), HashMap::new());

    loop {
        let (received, from) = usock.recv_from(&mut buf).await?;

        if let Some(to) = table_send.get(&from) {
            info!("{} bytes received from {}", received, from);

            usock.send_to(&buf[..received], to).await?;
        } else if from.ip().is_loopback() && table_recv.contains_key(&from.port()) {
            usock
                .send_to(&buf[..received], table_recv.get(&from.port()).unwrap())
                .await?;
        } else {
            info!("new connection. {} bytes received from {}", received, from);

            let ssock = UdpSocket::bind("0.0.0.0:0").await?;

            table_send.insert(from, ssock.local_addr().unwrap());
            table_recv.insert(ssock.local_addr().unwrap().port(), from);

            if config.client {
                tokio::spawn(client(ssock, usock.local_addr().unwrap(), dst));
            } else {
                tokio::spawn(server(ssock, usock.local_addr().unwrap(), dst));
            }

            usock.send_to(&buf[..received], table_send[&from]).await?;
        }
    }
}

async fn client(usock: UdpSocket, host: SocketAddr, dst: SocketAddr) -> Result<()> {
    let mut buf = vec![0_u8; BUF_SIZE];

    loop {
        let (received, from) = usock.recv_from(&mut buf).await?;

        if from.ip().is_loopback() && from.port() == host.port() {
            let s = base64::encode_config(&buf[..received], base64::URL_SAFE_NO_PAD);
            let s = s.as_bytes();

            let mut msg = Message::new();

            msg.set_id(rand::random())
                .add_queries((0..s.len()).step_by(NAME_L).map(|i| {
                    let mut q = Query::new();
                    q.set_name(Name::from_labels(vec![&s[i..min(i + NAME_L, s.len())]]).unwrap());
                    q
                }));

            info!("forwarding to {}", dst);

            usock.send_to(&msg.to_vec().unwrap(), dst).await?;
        } else if from == dst {
            info!("{} bytes received from {}", received, from);

            match Message::from_vec(&buf[..received]) {
                Ok(msg) => {
                    let mut s = String::new();

                    msg.answers().iter().for_each(|rec| {
                        s += &rec.data().unwrap().as_txt().unwrap().to_string();
                    });
                    match base64::decode_config(s, base64::URL_SAFE_NO_PAD) {
                        Ok(b) => {
                            usock.send_to(&b, host).await?;
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
        }
    }
}

async fn server(usock: UdpSocket, host: SocketAddr, dst: SocketAddr) -> Result<()> {
    let mut buf = vec![0_u8; BUF_SIZE];

    loop {
        let (received, from) = usock.recv_from(&mut buf).await?;

        if from.ip().is_loopback() && from.port() == host.port() {
            match Message::from_vec(&buf[..received]) {
                Ok(msg) => {
                    let mut s = String::new();

                    msg.queries().iter().for_each(|q| {
                        s += q.name().to_string().trim_end_matches('.');
                    });

                    match base64::decode_config(s, base64::URL_SAFE_NO_PAD) {
                        Ok(s) => {
                            info!("forwarding to {}", dst);

                            usock.send_to(&s, dst).await?;
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
        } else if from == dst {
            info!("{} bytes received from {}", received, from);

            let s = base64::encode_config(&buf[..received], base64::URL_SAFE_NO_PAD);

            let mut msg = Message::new();
            msg.set_id(rand::random())
                .add_answers((0..s.len()).step_by(TXT_L).map(|i| {
                    let mut r = Record::new();
                    r.set_record_type(RecordType::TXT)
                        .set_data(Some(RData::TXT(TXT::new(vec![String::from(
                            &s[i..min(i + TXT_L, s.len())],
                        )]))));
                    r
                }));

            usock.send_to(&msg.to_vec().unwrap(), host).await?;
        }
    }
}
