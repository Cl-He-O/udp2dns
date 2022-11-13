use clap::Parser;
use log::{info, warn};
use std::{cmp::min, collections::HashMap, io::Result, net::ToSocketAddrs};

use tokio::{net::UdpSocket, task::JoinHandle};

use trust_dns_proto::{
    op::Message,
    rr::{rdata::TXT, RData, Record, RecordType},
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

            let host = usock.local_addr().unwrap();

            let _: JoinHandle<Result<()>> = tokio::spawn(async move {
                let mut buf = vec![0_u8; BUF_SIZE];

                loop {
                    let (received, from) = ssock.recv_from(&mut buf).await?;

                    if from.ip().is_loopback() && from.port() == host.port() {
                        if let Some(msg) = if config.client {
                            Some(dns_reply_encode(&buf[..received]))
                        } else {
                            dns_reply_decode(&buf[..received])
                        } {
                            info!("forwarding to {}", dst);
                            ssock.send_to(&msg, dst).await?;
                        }
                    } else if from == dst {
                        info!("{} bytes received from {}", received, from);

                        if let Some(msg) = if config.client {
                            dns_reply_decode(&buf[..received])
                        } else {
                            Some(dns_reply_encode(&buf[..received]))
                        } {
                            ssock.send_to(&msg, host).await?;
                        }
                    }
                }
            });

            usock.send_to(&buf[..received], table_send[&from]).await?;
        }
    }
}

fn dns_reply_encode(buf: &[u8]) -> Vec<u8> {
    let s = base64::encode(buf);

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

    msg.to_vec().unwrap()
}

fn dns_reply_decode(buf: &[u8]) -> Option<Vec<u8>> {
    match Message::from_vec(&buf) {
        Ok(msg) => {
            let mut s = String::new();

            msg.answers().iter().for_each(|rec| {
                s += &rec.data().unwrap().as_txt().unwrap().to_string();
            });
            match base64::decode(s) {
                Ok(b) => return Some(b),
                Err(err) => {
                    warn!("{}", err);
                }
            }
        }
        Err(err) => {
            warn!("{}", err);
        }
    };
    None
}
