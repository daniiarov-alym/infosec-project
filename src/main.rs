use std::{env, net::Ipv4Addr};
use std::error::Error;
use pcap;
use etherparse::{self, Icmpv4Type, NetSlice, TransportSlice};
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("no filenames are given")
    }
    scan(&args[1..]);
    
}


fn scan(files: &[String]) {
    for file in files.iter() {
        if let Err(e) = scan_file(file) {
            panic!("Failed reading file: {} due to: {}", file, e);
        }
    }
}

fn scan_file(filename: &String) -> Result<(), Box<dyn Error>> {
    let mut capture = pcap::Capture::from_file(filename)?;
    
    let mut icmps: Vec<(Ipv4Addr, Ipv4Addr)> = Vec::new();
    let mut xmas_scans: Vec<(Ipv4Addr, usize)> = Vec::new();
    let mut null_scans: Vec<(Ipv4Addr, usize)> = Vec::new();
    let mut half_open_scans: Vec<(Ipv4Addr, usize)> = Vec::new();
    let mut udp_scans: Vec<(Ipv4Addr, usize)> = Vec::new();
    while let Ok(packet) = capture.next_packet() {
        //println!("read packet! {:?}", packet);
        let packet = etherparse::SlicedPacket::from_ethernet(packet.data)?;
        
        
        let mut source_addr = Ipv4Addr::new(0, 0, 0, 0);
        let mut dest_addr = Ipv4Addr::new(0,0,0,0);
    
        match packet.net {
            Some(t) => {
                match t {
                    NetSlice::Ipv4(s) => {
                        source_addr = s.header().source_addr();
                        dest_addr = s.header().destination_addr();
                    }
                    _ => {
                        
                    }
                }
            }
            None => {
                
            }
        }
        
        //println!("{:?}", packet);
        match packet.transport {
            Some(t) => { 
                //println!("{:?}", t);
                match t  {
                    TransportSlice::Icmpv4(s) => {
                        match s.icmp_type() {
                            Icmpv4Type::EchoRequest(h) => {
                                icmps.push((source_addr, dest_addr));
                            }
                            _ => {
                                
                            }
                        }
                    }
                    TransportSlice::Tcp(s) => {
                        if !s.ack() && !s.cwr() && !s.ece() && !s.fin() && !s.psh() && !s.rst() && !s.syn() && !s.urg() {
                            null_scans.push((source_addr, s.destination_port() as usize));
                        } else if s.urg() && s.fin() && s.psh() && !s.ack() && !s.rst() && !s.syn() {
                            xmas_scans.push((source_addr, s.destination_port() as usize));
                        } else if s.rst() && s.syn() && s.acknowledgment_number() == 0 {
                            half_open_scans.push((source_addr, s.destination_port() as usize));
                        }
                    }
                    TransportSlice::Udp(s) => {
                        if s.source_port() >= 32768 {
                            udp_scans.push((source_addr, s.destination_port() as usize));
                        }
                    }
                    _ => {
                        
                    }
                    
                }
            }
            None => {
                
            }
        }
    }
    println!("Results for file: {}", filename);
    println!("Null scans: \n\tTotal: {}\n\t{:#?}\n", null_scans.len(), null_scans);
    println!("Xmas scans: \n\tTotal: {}\n\t{:#?}\n", xmas_scans.len(), xmas_scans);
    println!("Half-open scans: \n\tTotal: {}\n\t{:#?}\n", half_open_scans.len(), half_open_scans);
    println!("UDP scans: \n\tTotal: {}\n\t{:#?}\n", udp_scans.len(), udp_scans);
    println!("ICMP requests: \n\tTotal: {}\n\t{:#?}\n", icmps.len(), icmps);
    Ok(())
}