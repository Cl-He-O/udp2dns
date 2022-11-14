use clap::Parser;
use log::{info, warn};
use std::{
    cmp::min,
    collections::HashMap,
    io::Result,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;

use tokio::{
    net::UdpSocket,
    select,
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
};

use trust_dns_proto::{
    op::Message,
    rr::{rdata::TXT, RData, Record, RecordType},
};

#[derive(Parser)]
struct Config {
    listen: String,
    dst: String,
    #[arg(short, long)]
    client: bool,
    #[arg(short, long)]
    loglevel: Option<String>,
    #[arg(short, long)]
    timeout: Option<u64>,
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

    let table = Arc::new(Mutex::new(HashMap::<
        SocketAddr,
        mpsc::UnboundedSender<Bytes>,
    >::new()));

    let (tx, mut rx) = mpsc::unbounded_channel::<(SocketAddr, Bytes)>();

    loop {
        select! {
            r = usock.recv_from(&mut buf) => {
                let (received,from) = r?;
                let mut tablel = table.lock().await;

                if from == dst {
                    info!("ignored connection from destination");
                }
                else if let Some(relayer) = tablel.get(&from) {
                    info!("{} bytes received from {}", received, from);
                    relayer.send(Bytes::copy_from_slice(&buf[..received])).unwrap();
                } else {
                    info!("new connection. {} bytes received from {}", received, from);

                    let (ttx, rx) = mpsc::unbounded_channel::<Bytes>();
                    tablel.insert(from, ttx);

                    tokio::spawn(relay(config.client,config.timeout.unwrap_or_else(||60),tx.clone(),rx,from,dst,table.clone()));

                    tablel.get(&from).unwrap().send(Bytes::copy_from_slice(&buf[..received])).unwrap();
                }
            },
            r = rx.recv() => {
                let (to,buf) = r.unwrap();

                info!("forwarding to {}",to);
                usock.send_to(&buf,to).await?;
            }
        };
    }
}

async fn relay(
    is_client: bool,
    timeout: u64,

    tx: UnboundedSender<(SocketAddr, Bytes)>,
    mut rx: UnboundedReceiver<Bytes>,
    src: SocketAddr,
    dst: SocketAddr,
    table: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Bytes>>>>,
) -> Result<()> {
    let mut buf = vec![0_u8; BUF_SIZE];

    let usock = UdpSocket::bind("0.0.0.0:0").await?;

    loop {
        select! {
            r = tokio::time::timeout(
                Duration::from_secs(timeout),
                usock.recv_from(&mut buf),
            )=>{
                let (received, from) = match r{
                    Ok(r) => r?,
                    Err(_) => {
                        info!("timeout, stopping relay for {}", src);
                        let mut tablel = table.lock().await;
                        tablel.remove(&src);
                        rx.close();
                        return Ok(());
                    }
                };

                if from == dst {
                    info!("{} bytes received from {}", received, from);
                    if let Some(msg) = if is_client {
                        dns_reply_decode(&buf[..received])
                    } else {
                        Some(dns_reply_encode(&buf[..received]))
                    } {
                        tx.send((src,msg)).unwrap();
                    }
                };
            },
            r = rx.recv()=>{
                info!("forwarding to {}",dst);
                usock.send_to(&r.unwrap(),dst).await?;
            }

        };
    }
}

fn dns_reply_encode(buf: &[u8]) -> Bytes {
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

    Bytes::from(msg.to_vec().unwrap())
}

fn dns_reply_decode(buf: &[u8]) -> Option<Bytes> {
    match Message::from_vec(&buf) {
        Ok(msg) => {
            let mut s = String::new();

            msg.answers().iter().for_each(|rec| {
                s += &rec.data().unwrap().as_txt().unwrap().to_string();
            });
            match base64::decode(s) {
                Ok(b) => return Some(Bytes::from(b)),
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
