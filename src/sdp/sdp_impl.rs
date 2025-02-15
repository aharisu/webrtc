use std::{
    fmt::{self, Display, Formatter},
    str,
};

#[derive(Debug)]
pub struct SdpMessage {
    pub version: u8,
    pub origin: SdpOrigin,
    pub session_name: String,
    pub session_info: Option<String>,
    pub uri: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub connection_info: Option<SdpConnectionInfo>,
    pub bandwidth: Option<u32>,
    pub time_descriptions: Vec<SdpTimeDescription>,
    pub attributes: Vec<SdpAttribute>,
    pub media_descriptions: Vec<SdpMediaDescription>,
}

#[derive(Debug)]
pub struct SdpOrigin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub nettype: String,
    pub addrtype: String,
    pub unicast_address: String,
}

#[derive(Debug)]
pub struct SdpConnectionInfo {
    pub nettype: String,
    pub addrtype: String,
    pub connection_address: ConnectionAddress,
}

#[derive(Debug, PartialEq)]
pub enum ConnectionAddress {
    Unicast(String),
    MulticastIpv4 {
        base_address: String,
        ttl: u8,
        num_addresses: u8,
    },
    MulticastIpv6 {
        base_address: String,
        num_addresses: u8,
    },
}

impl Display for ConnectionAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ConnectionAddress::Unicast(address) => write!(f, "{}", address),
            ConnectionAddress::MulticastIpv4 {
                base_address,
                ttl,
                num_addresses,
            } => {
                if *num_addresses == 1 {
                    write!(f, "{}/{}", base_address, ttl)
                } else {
                    write!(f, "{}/{}{}", base_address, ttl, num_addresses)
                }
            }
            ConnectionAddress::MulticastIpv6 {
                base_address,
                num_addresses,
            } => {
                if *num_addresses == 1 {
                    write!(f, "{}", base_address)
                } else {
                    write!(f, "{}/{}", base_address, num_addresses)
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct SdpTimeDescription {
    pub start_time: u64,
    pub stop_time: u64,
    pub repeat_times: Vec<SdpRepeatTime>,
}

#[derive(Debug)]
pub struct SdpRepeatTime {
    pub interval: u64,
    pub duration: u64,
    pub offsets: Vec<u64>,
}

#[derive(Debug)]
pub struct SdpAttribute {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug)]
pub struct SdpMediaDescription {
    pub media: String,
    pub port: u16,
    pub proto: String,
    pub fmt: Vec<String>,
    pub connection_info: Option<SdpConnectionInfo>,
    pub bandwidth: Option<u32>,
    pub attributes: Vec<SdpAttribute>,
}

impl SdpMessage {
    pub fn from_bytes(
        bytes: &[u8],
        offset: usize,
        length: usize,
    ) -> Result<SdpMessage, &'static str> {
        let sdp_str =
            str::from_utf8(&bytes[offset..offset + length]).map_err(|_| "Invalid UTF-8")?;
        //TODO 単一の\rの場合もあり得るので対応が必要
        let mut lines = sdp_str.lines().peekable();

        let mut version = 0;
        let mut origin = None;
        let mut session_name = String::new();
        let mut session_info = None;
        let mut uri = None;
        let mut email = None;
        let mut phone = None;
        let mut connection_info = None;
        let mut bandwidth = None;
        let mut time_descriptions = Vec::new();
        let mut attributes = Vec::new();
        let mut media_descriptions = Vec::new();

        while let Some(line) = lines.next() {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                continue;
            }
            let (key, value) = (parts[0], parts[1]);
            match key {
                "v" => version = value.parse().map_err(|_| "Invalid version")?,
                "o" => origin = Some(parse_origin(value)?),
                "s" => session_name = value.to_string(),
                "i" => session_info = Some(value.to_string()),
                "u" => uri = Some(value.to_string()),
                "e" => email = Some(value.to_string()),
                "p" => phone = Some(value.to_string()),
                "c" => connection_info = Some(parse_connection_info(value)?),
                "b" => bandwidth = Some(value.parse().map_err(|_| "Invalid bandwidth")?),
                "t" => time_descriptions.push(parse_time_description(value, &mut lines)?),
                "a" => attributes.push(parse_attribute(value)),
                "m" => media_descriptions.push(parse_media_description(value, &mut lines)?),
                _ => {
                    // Ignore unknown keys
                    println!("Unknown key-value: {}:{}\n", key, value);
                }
            }
        }

        Ok(SdpMessage {
            version,
            origin: origin.ok_or("Missing origin")?,
            session_name,
            session_info,
            uri,
            email,
            phone,
            connection_info,
            bandwidth,
            time_descriptions,
            attributes,
            media_descriptions,
        })
    }

    pub fn to_bytes(&self, buffer: &mut [u8], offset: usize) -> Result<usize, &'static str> {
        let mut current_offset = offset;

        let mut sdp_str = String::new();

        sdp_str.push_str(&format!("v={}\r\n", self.version));
        sdp_str.push_str(&format!(
            "o={} {} {} {} {} {}\r\n",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.nettype,
            self.origin.addrtype,
            self.origin.unicast_address
        ));
        sdp_str.push_str(&format!("s={}\r\n", self.session_name));

        if let Some(ref info) = self.session_info {
            sdp_str.push_str(&format!("i={}\r\n", info));
        }

        if let Some(ref uri) = self.uri {
            sdp_str.push_str(&format!("u={}\r\n", uri));
        }

        if let Some(ref email) = self.email {
            sdp_str.push_str(&format!("e={}\r\n", email));
        }

        if let Some(ref phone) = self.phone {
            sdp_str.push_str(&format!("p={}\r\n", phone));
        }

        if let Some(ref conn_info) = self.connection_info {
            sdp_str.push_str(&format!(
                "c={} {} {}\r\n",
                conn_info.nettype, conn_info.addrtype, conn_info.connection_address
            ));
        }

        if let Some(bandwidth) = self.bandwidth {
            sdp_str.push_str(&format!("b={}\r\n", bandwidth));
        }

        for td in &self.time_descriptions {
            sdp_str.push_str(&format!("t={} {}\r\n", td.start_time, td.stop_time));
            for rt in &td.repeat_times {
                let offsets_str = rt
                    .offsets
                    .iter()
                    .map(|offset| offset.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                sdp_str.push_str(&format!(
                    "r={} {} {}\r\n",
                    rt.interval, rt.duration, offsets_str
                ));
            }
        }

        for attr in &self.attributes {
            if let Some(ref value) = attr.value {
                sdp_str.push_str(&format!("a={}:{}\r\n", attr.name, value));
            } else {
                sdp_str.push_str(&format!("a={}\r\n", attr.name));
            }
        }

        for md in &self.media_descriptions {
            sdp_str.push_str(&format!(
                "m={} {} {} {}\r\n",
                md.media,
                md.port,
                md.proto,
                md.fmt.join(" ")
            ));
            if let Some(ref conn_info) = md.connection_info {
                sdp_str.push_str(&format!(
                    "c={} {} {}\r\n",
                    conn_info.nettype, conn_info.addrtype, conn_info.connection_address
                ));
            }
            if let Some(bandwidth) = md.bandwidth {
                sdp_str.push_str(&format!("b={}\r\n", bandwidth));
            }
            for attr in &md.attributes {
                if let Some(ref value) = attr.value {
                    sdp_str.push_str(&format!("a={}:{}\r\n", attr.name, value));
                } else {
                    sdp_str.push_str(&format!("a={}\r\n", attr.name));
                }
            }
        }

        let sdp_bytes = sdp_str.as_bytes();
        if buffer.len() < current_offset + sdp_bytes.len() {
            return Err("Buffer too small");
        }

        buffer[current_offset..current_offset + sdp_bytes.len()].copy_from_slice(sdp_bytes);
        current_offset += sdp_bytes.len();

        Ok(current_offset)
    }
}

fn parse_origin(value: &str) -> Result<SdpOrigin, &'static str> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 6 {
        return Err("Invalid origin");
    }
    Ok(SdpOrigin {
        username: parts[0].to_string(),
        session_id: parts[1].parse().map_err(|_| "Invalid session_id")?,
        session_version: parts[2].parse().map_err(|_| "Invalid session_version")?,
        nettype: parts[3].to_string(),
        addrtype: parts[4].to_string(),
        unicast_address: parts[5].to_string(),
    })
}

fn parse_connection_info(value: &str) -> Result<SdpConnectionInfo, &'static str> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 3 {
        return Err("Invalid connection info");
    }
    let connection_address = parse_connection_address(parts[1], parts[2])?;
    Ok(SdpConnectionInfo {
        nettype: parts[0].to_string(),
        addrtype: parts[1].to_string(),
        connection_address,
    })
}

fn parse_connection_address(
    addrtype: &str,
    value: &str,
) -> Result<ConnectionAddress, &'static str> {
    match addrtype {
        "IP4" => {
            let parts: Vec<&str> = value.split('/').collect();
            if parts.len() == 1 {
                Ok(ConnectionAddress::Unicast(parts[0].to_string()))
            } else if parts.len() == 2 {
                let ttl = parts[1].parse().map_err(|_| "Invalid TTL")?;
                Ok(ConnectionAddress::MulticastIpv4 {
                    base_address: parts[0].to_string(),
                    ttl,
                    num_addresses: 1,
                })
            } else if parts.len() == 3 {
                let ttl = parts[1].parse().map_err(|_| "Invalid TTL")?;
                let num_addresses = parts[2]
                    .parse()
                    .map_err(|_| "Invalid number of addresses")?;
                Ok(ConnectionAddress::MulticastIpv4 {
                    base_address: parts[0].to_string(),
                    ttl,
                    num_addresses,
                })
            } else {
                Err("Invalid IPv4 connection address")
            }
        }
        "IP6" => {
            let parts: Vec<&str> = value.split('/').collect();
            if parts.len() == 1 {
                Ok(ConnectionAddress::Unicast(parts[0].to_string()))
            } else if parts.len() == 2 {
                let num_addresses = parts[1]
                    .parse()
                    .map_err(|_| "Invalid number of addresses")?;
                Ok(ConnectionAddress::MulticastIpv6 {
                    base_address: parts[0].to_string(),
                    num_addresses,
                })
            } else {
                Err("Invalid IPv6 connection address")
            }
        }
        _ => Err("Unknown address type"),
    }
}

fn parse_time_description(
    value: &str,
    lines: &mut std::iter::Peekable<std::str::Lines>,
) -> Result<SdpTimeDescription, &'static str> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 2 {
        return Err("Invalid time description");
    }
    let start_time = parts[0].parse().map_err(|_| "Invalid start_time")?;
    let stop_time = parts[1].parse().map_err(|_| "Invalid stop_time")?;
    let mut repeat_times = Vec::new();

    while let Some(line) = lines.peek() {
        if line.starts_with('r') {
            repeat_times.push(parse_repeat_time(&line[2..])?);
            lines.next();
        } else {
            break;
        }
    }

    Ok(SdpTimeDescription {
        start_time,
        stop_time,
        repeat_times,
    })
}

fn parse_repeat_time(value: &str) -> Result<SdpRepeatTime, &'static str> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Invalid repeat time");
    }
    let interval = parts[0].parse().map_err(|_| "Invalid interval")?;
    let duration = parts[1].parse().map_err(|_| "Invalid duration")?;
    let offsets = parts[2..]
        .iter()
        .map(|&s| s.parse().map_err(|_| "Invalid offset"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SdpRepeatTime {
        interval,
        duration,
        offsets,
    })
}

fn parse_attribute(value: &str) -> SdpAttribute {
    let parts: Vec<&str> = value.splitn(2, ':').collect();
    SdpAttribute {
        name: parts[0].to_string(),
        value: parts.get(1).map(|&v| v.to_string()),
    }
}

fn parse_media_description(
    value: &str,
    lines: &mut std::iter::Peekable<std::str::Lines>,
) -> Result<SdpMediaDescription, &'static str> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 4 {
        return Err("Invalid media description");
    }
    let media = parts[0].to_string();
    let port = parts[1].parse().map_err(|_| "Invalid port")?;
    let proto = parts[2].to_string();
    let fmt = parts[3..].iter().map(|&s| s.to_string()).collect();
    let mut connection_info = None;
    let mut bandwidth = None;
    let mut attributes = Vec::new();

    while let Some(line) = lines.peek() {
        if line.starts_with('c') {
            connection_info = Some(parse_connection_info(&line[2..])?);
            lines.next();
        } else if line.starts_with('b') {
            bandwidth = Some(line[2..].parse().map_err(|_| "Invalid bandwidth")?);
            lines.next();
        } else if line.starts_with('a') {
            attributes.push(parse_attribute(&line[2..]));
            lines.next();
        } else {
            break;
        }
    }

    Ok(SdpMediaDescription {
        media,
        port,
        proto,
        fmt,
        connection_info,
        bandwidth,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let sdp_data = b"v=0\r\no=- 2890844526 2890842807 IN IP4 127.0.0.1\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nt=2873397496 2873404696\r\nm=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let sdp_message = SdpMessage::from_bytes(sdp_data, 0, sdp_data.len()).unwrap();

        assert_eq!(sdp_message.version, 0);
        assert_eq!(sdp_message.origin.username, "-");
        assert_eq!(sdp_message.origin.session_id, 2890844526);
        assert_eq!(sdp_message.origin.session_version, 2890842807);
        assert_eq!(sdp_message.origin.nettype, "IN");
        assert_eq!(sdp_message.origin.addrtype, "IP4");
        assert_eq!(sdp_message.origin.unicast_address, "127.0.0.1");
        assert_eq!(sdp_message.session_name, "SDP Seminar");
        assert!(sdp_message.connection_info.is_some());
        assert_eq!(
            sdp_message.connection_info.unwrap().connection_address,
            ConnectionAddress::MulticastIpv4 {
                base_address: "224.2.17.12".to_string(),
                ttl: 127,
                num_addresses: 1
            }
        );
        assert_eq!(sdp_message.time_descriptions.len(), 1);
        assert_eq!(sdp_message.time_descriptions[0].start_time, 2873397496);
        assert_eq!(sdp_message.time_descriptions[0].stop_time, 2873404696);
        assert_eq!(sdp_message.media_descriptions.len(), 1);
        assert_eq!(sdp_message.media_descriptions[0].media, "audio");
        assert_eq!(sdp_message.media_descriptions[0].port, 49170);
        assert_eq!(sdp_message.media_descriptions[0].proto, "RTP/AVP");
        assert_eq!(sdp_message.media_descriptions[0].fmt, vec!["0"]);
        assert_eq!(sdp_message.media_descriptions[0].attributes.len(), 1);
        assert_eq!(
            sdp_message.media_descriptions[0].attributes[0].name,
            "rtpmap"
        );
        assert_eq!(
            sdp_message.media_descriptions[0].attributes[0].value,
            Some("0 PCMU/8000".to_string())
        );
    }

    #[test]
    fn test_from_bytes_ipv6() {
        let sdp_data = b"v=0\r\no=- 2890844526 2890842807 IN IP6 2001:db8::1\r\ns=SDP Seminar\r\nc=IN IP6 2001:db8::2\r\nt=2873397496 2873404696\r\nm=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let sdp_message = SdpMessage::from_bytes(sdp_data, 0, sdp_data.len()).unwrap();

        assert_eq!(sdp_message.version, 0);
        assert_eq!(sdp_message.origin.username, "-");
        assert_eq!(sdp_message.origin.session_id, 2890844526);
        assert_eq!(sdp_message.origin.session_version, 2890842807);
        assert_eq!(sdp_message.origin.nettype, "IN");
        assert_eq!(sdp_message.origin.addrtype, "IP6");
        assert_eq!(sdp_message.origin.unicast_address, "2001:db8::1");
        assert_eq!(sdp_message.session_name, "SDP Seminar");
        assert!(sdp_message.connection_info.is_some());
        assert_eq!(
            sdp_message.connection_info.unwrap().connection_address,
            ConnectionAddress::Unicast("2001:db8::2".to_string())
        );
        assert_eq!(sdp_message.time_descriptions.len(), 1);
        assert_eq!(sdp_message.time_descriptions[0].start_time, 2873397496);
        assert_eq!(sdp_message.time_descriptions[0].stop_time, 2873404696);
        assert_eq!(sdp_message.media_descriptions.len(), 1);
        assert_eq!(sdp_message.media_descriptions[0].media, "audio");
        assert_eq!(sdp_message.media_descriptions[0].port, 49170);
        assert_eq!(sdp_message.media_descriptions[0].proto, "RTP/AVP");
        assert_eq!(sdp_message.media_descriptions[0].fmt, vec!["0"]);
        assert_eq!(sdp_message.media_descriptions[0].attributes.len(), 1);
        assert_eq!(
            sdp_message.media_descriptions[0].attributes[0].name,
            "rtpmap"
        );
        assert_eq!(
            sdp_message.media_descriptions[0].attributes[0].value,
            Some("0 PCMU/8000".to_string())
        );
    }

    #[test]
    fn test_parse_connection_address_ipv4_unicast() {
        let addr = "192.0.2.1";
        let result = parse_connection_address("IP4", addr).unwrap();
        if let ConnectionAddress::Unicast(address) = result {
            assert_eq!(address, "192.0.2.1");
        } else {
            panic!("Parsed connection address is not IPv4 unicast");
        }
    }

    #[test]
    fn test_parse_connection_address_ipv4_multicast() {
        let addr = "233.252.0.1/127/3";
        let result = parse_connection_address("IP4", addr).unwrap();
        if let ConnectionAddress::MulticastIpv4 {
            base_address,
            ttl,
            num_addresses,
        } = result
        {
            assert_eq!(base_address, "233.252.0.1");
            assert_eq!(ttl, 127);
            assert_eq!(num_addresses, 3);
        } else {
            panic!("Parsed connection address is not IPv4 multicast");
        }
    }

    #[test]
    fn test_parse_connection_address_ipv6_unicast() {
        let addr = "2001:db8::1";
        let result = parse_connection_address("IP6", addr).unwrap();
        if let ConnectionAddress::Unicast(address) = result {
            assert_eq!(address, "2001:db8::1");
        } else {
            panic!("Parsed connection address is not IPv6 unicast");
        }
    }

    #[test]
    fn test_parse_connection_address_ipv6_multicast() {
        let addr = "ff00::db8:0:101/3";
        let result = parse_connection_address("IP6", addr).unwrap();
        if let ConnectionAddress::MulticastIpv6 {
            base_address,
            num_addresses,
        } = result
        {
            assert_eq!(base_address, "ff00::db8:0:101");
            assert_eq!(num_addresses, 3);
        } else {
            panic!("Parsed connection address is not IPv6 multicast");
        }
    }

    #[test]
    fn test_parse_connection_address_invalid_ipv4() {
        let addr = "233.252.0.1/invalid";
        let result = parse_connection_address("IP4", addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_connection_address_invalid_ipv6() {
        let addr = "ff00::db8:0:101/invalid";
        let result = parse_connection_address("IP6", addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_bytes() {
        let sdp_message = SdpMessage {
            version: 0,
            origin: SdpOrigin {
                username: "-".to_string(),
                session_id: 2890844526,
                session_version: 2890842807,
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "127.0.0.1".to_string(),
            },
            session_name: "SDP Seminar".to_string(),
            session_info: None,
            uri: None,
            email: None,
            phone: None,
            connection_info: Some(SdpConnectionInfo {
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                connection_address: ConnectionAddress::MulticastIpv4 {
                    base_address: "224.2.17.12".to_string(),
                    ttl: 127,
                    num_addresses: 1,
                },
            }),
            bandwidth: None,
            time_descriptions: vec![SdpTimeDescription {
                start_time: 2873397496,
                stop_time: 2873404696,
                repeat_times: vec![],
            }],
            attributes: vec![],
            media_descriptions: vec![SdpMediaDescription {
                media: "audio".to_string(),
                port: 49170,
                proto: "RTP/AVP".to_string(),
                fmt: vec!["0".to_string()],
                connection_info: None,
                bandwidth: None,
                attributes: vec![SdpAttribute {
                    name: "rtpmap".to_string(),
                    value: Some("0 PCMU/8000".to_string()),
                }],
            }],
        };

        let mut buffer = vec![0u8; 1024];
        let offset = 0;
        let result = sdp_message.to_bytes(&mut buffer, offset).unwrap();
        let expected_sdp = "v=0\r\no=- 2890844526 2890842807 IN IP4 127.0.0.1\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nt=2873397496 2873404696\r\nm=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(&buffer[..result], expected_sdp.as_bytes());
    }

    #[test]
    fn test_connection_address_to_string() {
        let unicast = ConnectionAddress::Unicast("192.0.2.1".to_string());
        assert_eq!(unicast.to_string(), "192.0.2.1");

        let multicast_ipv4 = ConnectionAddress::MulticastIpv4 {
            base_address: "233.252.0.1".to_string(),
            ttl: 127,
            num_addresses: 3,
        };
        assert_eq!(multicast_ipv4.to_string(), "233.252.0.1/1273");

        let multicast_ipv6 = ConnectionAddress::MulticastIpv6 {
            base_address: "ff00::db8:0:101".to_string(),
            num_addresses: 3,
        };
        assert_eq!(multicast_ipv6.to_string(), "ff00::db8:0:101/3");
    }

    #[test]
    fn test_multiple_media_descriptions() {
        let sdp_data = b"v=0\r\no=- 2890844526 2890842807 IN IP4 127.0.0.1\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nt=2873397496 2873404696\r\nm=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\nm=video 51372 RTP/AVP 99\r\na=rtpmap:99 H263-1998/90000\r\n";
        let sdp_message = SdpMessage::from_bytes(sdp_data, 0, sdp_data.len()).unwrap();

        assert_eq!(sdp_message.version, 0);
        assert_eq!(sdp_message.origin.username, "-");
        assert_eq!(sdp_message.origin.session_id, 2890844526);
        assert_eq!(sdp_message.origin.session_version, 2890842807);
        assert_eq!(sdp_message.origin.nettype, "IN");
        assert_eq!(sdp_message.origin.addrtype, "IP4");
        assert_eq!(sdp_message.origin.unicast_address, "127.0.0.1");
        assert_eq!(sdp_message.session_name, "SDP Seminar");
        assert!(sdp_message.connection_info.is_some());
        assert_eq!(
            sdp_message.connection_info.unwrap().connection_address,
            ConnectionAddress::MulticastIpv4 {
                base_address: "224.2.17.12".to_string(),
                ttl: 127,
                num_addresses: 1
            }
        );
        assert_eq!(sdp_message.time_descriptions.len(), 1);
        assert_eq!(sdp_message.time_descriptions[0].start_time, 2873397496);
        assert_eq!(sdp_message.time_descriptions[0].stop_time, 2873404696);
        assert_eq!(sdp_message.media_descriptions.len(), 2);

        let audio_media = &sdp_message.media_descriptions[0];
        assert_eq!(audio_media.media, "audio");
        assert_eq!(audio_media.port, 49170);
        assert_eq!(audio_media.proto, "RTP/AVP");
        assert_eq!(audio_media.fmt, vec!["0"]);
        assert_eq!(audio_media.attributes.len(), 1);
        assert_eq!(audio_media.attributes[0].name, "rtpmap");
        assert_eq!(audio_media.attributes[0].value, Some("0 PCMU/8000".to_string()));

        let video_media = &sdp_message.media_descriptions[1];
        assert_eq!(video_media.media, "video");
        assert_eq!(video_media.port, 51372);
        assert_eq!(video_media.proto, "RTP/AVP");
        assert_eq!(video_media.fmt, vec!["99"]);
        assert_eq!(video_media.attributes.len(), 1);
        assert_eq!(video_media.attributes[0].name, "rtpmap");
        assert_eq!(video_media.attributes[0].value, Some("99 H263-1998/90000".to_string()));
    }
}
