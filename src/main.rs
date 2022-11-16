use clap::Parser;
use log::{debug, info, warn};
use std::{
    cmp::min,
    collections::HashMap,
    io::Result,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use bytes::Bytes;

use tokio::{
    net::UdpSocket,
    select,
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex,
    },
    time::{Duration, Instant},
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
    loglevel: Option<String>, // default "warn"
    #[arg(short, long)]
    timeout: Option<u64>, // in seconds. Default 60
    #[arg(short, long)]
    bufsize: Option<usize>, // default 20
}

const BUF_SIZE: usize = 0x1000;
const TXT_L: usize = 255;

type Table = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    env_logger::builder()
        .parse_filters(&config.loglevel.unwrap_or("warn".to_string()))
        .init();

    let dst = config.dst.to_socket_addrs().unwrap().next().unwrap();
    let cbufsize = config.bufsize.unwrap_or_else(|| 20);

    let usock = UdpSocket::bind(config.listen).await?;

    warn!("listening on {}", usock.local_addr()?);

    let mut buf = [0_u8; BUF_SIZE];

    let table: Table = Arc::new(Mutex::new(HashMap::new()));

    let (tx, mut rx) = mpsc::channel::<(SocketAddr, Bytes)>(cbufsize);

    loop {
        select! {
            r = usock.recv_from(&mut buf) => {
                let (received,from) = r?;
                let mut tablel = table.lock().await;

                if from == dst {
                    info!("ignored connection from destination");
                }
                else if let Some(relayer) = tablel.get(&from) {
                    debug!("{} bytes received from {}", received, from);
                    relayer.try_send(Bytes::copy_from_slice(&buf[..received])).ok();
                } else {
                    info!("new connection from {}", from);
                    debug!("{} bytes received from {}", received, from);

                    let (ttx, rx) = mpsc::channel::<Bytes>(cbufsize);
                    tablel.insert(from, ttx);

                    tokio::spawn(relay(config.client,config.timeout.unwrap_or_else(||60),tx.clone(),rx,from,dst,table.clone()));

                    tablel.get(&from).unwrap().try_send(Bytes::copy_from_slice(&buf[..received])).ok();
                }
            },
            r = rx.recv() => {
                let (to,buf) = r.unwrap();

                debug!("forwarding to {}",to);
                usock.send_to(&buf,to).await?;
            }
        };
    }
}

async fn relay(
    is_client: bool,
    timeout: u64,

    tx: Sender<(SocketAddr, Bytes)>,
    mut rx: Receiver<Bytes>,
    src: SocketAddr,
    dst: SocketAddr,
    table: Table,
) -> Result<()> {
    let mut buf = [0_u8; BUF_SIZE];

    let usock = UdpSocket::bind("0.0.0.0:0").await?;

    let mut timer = Instant::now();

    loop {
        select! {
            r = tokio::time::timeout_at(
                timer + Duration::from_secs(timeout),
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
                    debug!("{} bytes received from {}", received, from);
                    if let Some(msg) = if is_client {
                        dns_reply_decode(&buf[..received])
                    } else {
                        Some(dns_reply_encode(&buf[..received]))
                    } {
                        tx.try_send((src,msg)).ok();

                        timer = Instant::now();
                    }
                };
            },
            r = rx.recv()=>{
                debug!("forwarding to {}",dst);
                usock.send_to(&r.unwrap(),dst).await?;

                timer = Instant::now();
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
