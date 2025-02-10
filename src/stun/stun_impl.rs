use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug)]
pub struct StunMessage {
    pub message_type: u16,
    pub message_length: u16,
    pub magic_cookie: u32,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<StunAttribute>,
}

#[derive(Debug)]
pub enum StunAttribute {
    MappedAddress(SocketAddr),
    Username(String),
    MessageIntegrity(Vec<u8>),
    ErrorCode(u16, String),
    UnknownAttributes(Vec<u16>),
    Realm(String),
    Nonce(String),
    XorMappedAddress(SocketAddr),
    Software(String),
    AlternateServer(SocketAddr),
    Fingerprint(u32),
    // 他の属性も必要に応じて追加
}

#[derive(Debug)]
pub enum StunMessageType {
    BindingRequest,
    BindingResponse,
    BindingErrorResponse,
    Unknown(u16),
}

impl StunMessageType {
    pub fn from_u16(value: u16) -> StunMessageType {
        match value {
            0x0001 => StunMessageType::BindingRequest,
            0x0101 => StunMessageType::BindingResponse,
            0x0111 => StunMessageType::BindingErrorResponse,
            _ => StunMessageType::Unknown(value),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            StunMessageType::BindingRequest => 0x0001,
            StunMessageType::BindingResponse => 0x0101,
            StunMessageType::BindingErrorResponse => 0x0111,
            StunMessageType::Unknown(value) => *value,
        }
    }
}

impl StunMessage {
    pub fn new(
        message_type: StunMessageType,
        transaction_id: [u8; 12],
        attributes: Vec<StunAttribute>,
    ) -> StunMessage {
        let mut message_length = 0;
        for attribute in &attributes {
            message_length += 4;
            match attribute {
                StunAttribute::MappedAddress(address) => {
                    message_length += match address {
                        SocketAddr::V4(_) => 8,
                        SocketAddr::V6(_) => 20,
                    };
                }
                // 他の属性も必要に応じて追加
                _ => {}
            }
        }
        StunMessage {
            message_type: message_type.to_u16(),
            message_length: message_length,
            magic_cookie: 0x2112A442,
            transaction_id,
            attributes,
        }
    }

    pub fn make_new_transaction_id() -> [u8; 12] {
        let mut transaction_id = [0; 12];
        for i in 0..12 {
            transaction_id[i] = rand::random();
        }
        transaction_id
    }

    pub fn equals_transaction_id(&self, other: &StunMessage) -> bool {
        self.transaction_id == other.transaction_id
    }

    pub fn to_bytes(&self, buffer: &mut [u8], offset: usize) -> Result<usize, &'static str> {
        if buffer.len() < offset + 20 + self.message_length as usize {
            return Err("Buffer too small");
        }

        buffer[offset..offset + 2].copy_from_slice(&self.message_type.to_be_bytes());
        buffer[offset + 2..offset + 4].copy_from_slice(&self.message_length.to_be_bytes());
        buffer[offset + 4..offset + 8].copy_from_slice(&self.magic_cookie.to_be_bytes());
        buffer[offset + 8..offset + 20].copy_from_slice(&self.transaction_id);

        let mut current_offset = offset + 20;
        for attribute in &self.attributes {
            match attribute {
                StunAttribute::MappedAddress(address) => {
                    buffer[current_offset..current_offset + 2]
                        .copy_from_slice(&0x0001u16.to_be_bytes());
                    let length = match address {
                        SocketAddr::V4(_) => 8,
                        SocketAddr::V6(_) => 20,
                    };
                    buffer[current_offset + 2..current_offset + 4]
                        .copy_from_slice(&(length as u16).to_be_bytes());
                    buffer[current_offset + 4] = 0;
                    match address {
                        SocketAddr::V4(addr) => {
                            buffer[current_offset + 5] = 0x01;
                            buffer[current_offset + 6..current_offset + 8]
                                .copy_from_slice(&addr.port().to_be_bytes());
                            buffer[current_offset + 8..current_offset + 12]
                                .copy_from_slice(&addr.ip().octets());
                        }
                        SocketAddr::V6(addr) => {
                            buffer[current_offset + 5] = 0x02;
                            buffer[current_offset + 6..current_offset + 8]
                                .copy_from_slice(&addr.port().to_be_bytes());
                            buffer[current_offset + 8..current_offset + 24]
                                .copy_from_slice(&addr.ip().octets());
                        }
                    }
                    current_offset += 4 + length;
                }
                // 他の属性も必要に応じて追加
                _ => return Err("Unknown attribute type"),
            }
        }

        Ok(current_offset)
    }

    pub fn from_bytes(
        bytes: &[u8],
        offset: usize,
        length: usize,
    ) -> Result<StunMessage, &'static str> {
        if length < 20 {
            return Err("Invalid STUN message length");
        }

        let message_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let message_length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let magic_cookie = u32::from_be_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        if (magic_cookie & 0xFFFFFFFF) != 0x2112A442 {
            return Err("Invalid magic cookie");
        }

        let transaction_id = [
            bytes[offset + 8],
            bytes[offset + 9],
            bytes[offset + 10],
            bytes[offset + 11],
            bytes[offset + 12],
            bytes[offset + 13],
            bytes[offset + 14],
            bytes[offset + 15],
            bytes[offset + 16],
            bytes[offset + 17],
            bytes[offset + 18],
            bytes[offset + 19],
        ];

        let mut attributes = Vec::new();
        let mut current_offset = offset + 20;
        while current_offset < offset + length {
            let attr_type = u16::from_be_bytes([bytes[current_offset], bytes[current_offset + 1]]);
            let attr_length =
                u16::from_be_bytes([bytes[current_offset + 2], bytes[current_offset + 3]]) as usize;
            let attr_value = &bytes[current_offset + 4..current_offset + 4 + attr_length];

            let attribute = match attr_type {
                0x0001 => {
                    let port = u16::from_be_bytes([attr_value[2], attr_value[3]]);
                    let address = match attr_value[1] {
                        0x01 => {
                            let ip = Ipv4Addr::new(
                                attr_value[4],
                                attr_value[5],
                                attr_value[6],
                                attr_value[7],
                            );
                            SocketAddr::new(ip.into(), port)
                        }
                        0x02 => {
                            let ip = Ipv6Addr::new(
                                u16::from_be_bytes([attr_value[4], attr_value[5]]),
                                u16::from_be_bytes([attr_value[6], attr_value[7]]),
                                u16::from_be_bytes([attr_value[8], attr_value[9]]),
                                u16::from_be_bytes([attr_value[10], attr_value[11]]),
                                u16::from_be_bytes([attr_value[12], attr_value[13]]),
                                u16::from_be_bytes([attr_value[14], attr_value[15]]),
                                u16::from_be_bytes([attr_value[16], attr_value[17]]),
                                u16::from_be_bytes([attr_value[18], attr_value[19]]),
                            );
                            SocketAddr::new(ip.into(), port)
                        }
                        _ => return Err("Invalid address family"),
                    };
                    StunAttribute::MappedAddress(address)
                }
                0x0006 => {
                    let username = String::from_utf8(attr_value.to_vec())
                        .map_err(|_| "Invalid UTF-8 in USERNAME attribute")?;
                    StunAttribute::Username(username)
                }
                0x0008 => StunAttribute::MessageIntegrity(attr_value.to_vec()),
                0x0009 => {
                    let error_code = u16::from_be_bytes([attr_value[2], attr_value[3]]);
                    let reason_phrase = String::from_utf8(attr_value[4..].to_vec())
                        .map_err(|_| "Invalid UTF-8 in ERROR-CODE attribute")?;
                    StunAttribute::ErrorCode(error_code, reason_phrase)
                }
                0x000A => {
                    let unknown_attributes = attr_value
                        .chunks(2)
                        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                        .collect();
                    StunAttribute::UnknownAttributes(unknown_attributes)
                }
                0x0014 => {
                    let realm = String::from_utf8(attr_value.to_vec())
                        .map_err(|_| "Invalid UTF-8 in REALM attribute")?;
                    StunAttribute::Realm(realm)
                }
                0x0015 => {
                    let nonce = String::from_utf8(attr_value.to_vec())
                        .map_err(|_| "Invalid UTF-8 in NONCE attribute")?;
                    StunAttribute::Nonce(nonce)
                }
                0x0020 => {
                    let port = u16::from_be_bytes([attr_value[2], attr_value[3]])
                        ^ ((magic_cookie >> 16) as u16);
                    let address = match attr_value[1] {
                        0x01 => {
                            let ip = Ipv4Addr::new(
                                attr_value[4] ^ ((magic_cookie >> 24) as u8),
                                attr_value[5] ^ ((magic_cookie >> 16) as u8),
                                attr_value[6] ^ ((magic_cookie >> 8) as u8),
                                attr_value[7] ^ (magic_cookie as u8),
                            );
                            SocketAddr::new(ip.into(), port)
                        }
                        0x02 => {
                            let ip = Ipv6Addr::new(
                                u16::from_be_bytes([attr_value[4], attr_value[5]])
                                    ^ ((magic_cookie >> 16) as u16),
                                u16::from_be_bytes([attr_value[6], attr_value[7]])
                                    ^ ((magic_cookie >> 16) as u16),
                                u16::from_be_bytes([attr_value[8], attr_value[9]])
                                    ^ ((magic_cookie >> 16) as u16),
                                u16::from_be_bytes([attr_value[10], attr_value[11]])
                                    ^ ((magic_cookie >> 16) as u16),
                                u16::from_be_bytes([attr_value[12], attr_value[13]])
                                    ^ ((magic_cookie >> 16) as u16),
                                u16::from_be_bytes([attr_value[14], attr_value[15]])
                                    ^ ((magic_cookie >> 16) as u16),
                                u16::from_be_bytes([attr_value[16], attr_value[17]])
                                    ^ ((magic_cookie >> 16) as u16),
                                u16::from_be_bytes([attr_value[18], attr_value[19]])
                                    ^ ((magic_cookie >> 16) as u16),
                            );
                            SocketAddr::new(ip.into(), port)
                        }
                        _ => return Err("Invalid address family"),
                    };
                    StunAttribute::XorMappedAddress(address)
                }
                // 他の属性も必要に応じて追加
                _ => {
                    println!("Unknown attribute type: 0x{:04x}", attr_type);
                    StunAttribute::UnknownAttributes(vec![attr_type])
                }
            };

            attributes.push(attribute);
            current_offset += 4 + attr_length;
        }

        Ok(StunMessage {
            message_type,
            message_length,
            magic_cookie,
            transaction_id,
            attributes,
        })
    }
}
