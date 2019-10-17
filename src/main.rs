use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::{env, io};

use rand;

use failure::Error;

use termion::color;

use tokio::runtime::current_thread::Runtime;

use trust_dns::client::{ClientConnection, ClientFuture};
use trust_dns::op::DnsResponse;
use trust_dns::rr::RData;
use trust_dns::rr::RData::{A, CNAME, NS};
use trust_dns::rr::{DNSClass, Name, RecordType};
use trust_dns::udp::UdpClientConnection;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::{DnsRequest, DnsRequestOptions};

use trust_dns_resolver::Resolver;

fn query_loop(
    request: DnsRequest,
    address: IpAddr,
    resolver: &Resolver,
    indent: usize,
) -> Result<(), io::Error> {
    let connection = UdpClientConnection::new(SocketAddr::new(address, 53))?;
    let stream = connection.new_stream(None);
    let (bg, mut handle) = ClientFuture::connect(stream);

    let r = handle.send(request.clone());

    let mut reactor = Runtime::new()?;
    let response: DnsResponse = reactor.spawn(bg).block_on(r)?;

    if response.name_server_count() != 0 && response.answer_count() == 0 {
        println!(
            "{:indent$}{}This server is not authorative{}",
            "",
            color::Fg(color::LightBlue),
            color::Fg(color::Reset),
            indent = indent
        );
        for ns in response.name_servers() {
            if let NS(name) = ns.rdata() {
                let fqdn = name.to_utf8();
                let ips = resolver.ipv4_lookup(&fqdn)?;
                for ip in ips {
                    println!(
                        "{:indent$}{}Querying {} ({}){}",
                        "",
                        color::Fg(color::LightBlue),
                        fqdn,
                        ip,
                        color::Fg(color::Reset),
                        indent = indent
                    );
                    query_loop(request.clone(), IpAddr::from(ip), resolver, indent + 4)?;
                }
            }
        }
    } else if response.answer_count() == 0 {
        println!(
            "{:indent$}{}Unable to resolve. Got: {:#?}{}",
            "",
            color::Fg(color::Red),
            response,
            color::Fg(color::Reset),
            indent = indent
        );
    } else {
        for a in response.answers() {
            println!(
                "{:indent$}{} {} -> {}{}",
                "",
                color::Fg(color::Green),
                response.queries()[0].name().to_utf8(),
                pretty_print(&a.rdata()),
                color::Fg(color::Reset),
                indent = indent
            );
        }
    }

    Ok(())
}

fn pretty_print(rdata: &RData) -> String {
    match rdata {
        CNAME(name) => format!("CNAME {}", name),
        A(ip) => format!("{}", ip),
        _ => format!("{:#?}", rdata),
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    let host = &args[1];
    let nameserver = &args[2];
    let resolver = Resolver::from_system_conf()?;

    let address = nameserver.parse()?;

    let name = Name::from_str(host)?;
    let mut query = Query::query(name, RecordType::A);
    query.set_query_class(DNSClass::IN);

    let mut message: Message = Message::new();
    let id: u16 = rand::random();
    message.add_query(query);
    message
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);

    let request = DnsRequest::new(message, DnsRequestOptions::default());
    query_loop(request, address, &resolver, 0)?;
    Ok(())
}
