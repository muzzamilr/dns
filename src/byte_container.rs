use super::errors::DnsErrors;

#[derive(Debug)]
pub struct ByteContainer {
    pub list: [u8; 512],
    pub pos: usize,
}

impl Default for ByteContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteContainer {
    pub fn new() -> ByteContainer {
        ByteContainer {
            list: [0; 512],
            pos: 0,
        }
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn skip(&mut self, steps: usize) -> Result<(), DnsErrors> {
        self.pos += steps;
        Ok(())
    }

    pub fn change_position(&mut self, position: usize) -> Result<(), DnsErrors> {
        self.pos = position;
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8, DnsErrors> {
        if self.pos >= 512 {
            return Err(DnsErrors::ByteContainerError);
        }
        let val = self.list[self.pos];
        self.pos += 1;
        Ok(val)
    }

    pub fn read_u16(&mut self) -> Result<u16, DnsErrors> {
        let val = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(val)
    }

    pub fn read_u32(&mut self) -> Result<u32, DnsErrors> {
        let val = ((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32);
        Ok(val)
    }

    pub fn get(&mut self, pos: usize) -> Result<u8, DnsErrors> {
        if pos >= 512 {
            return Err(DnsErrors::ByteContainerError);
        }
        Ok(self.list[pos])
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], DnsErrors> {
        if start + len >= 512 {
            return Err(DnsErrors::ByteContainerError);
        }
        Ok(&self.list[start..start + len as usize])
    }

    pub fn read_qname(
        &mut self,
        // outstr: &mut String
    ) -> Result<String, DnsErrors> {
        let mut outstr = "".to_string();
        let mut pos = self.position();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop {
            if jumps_performed > max_jumps {
                return Err(DnsErrors::ByteContainerError);
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.change_position(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            } else {
                pos += 1;

                if len == 0 {
                    break;
                }

                outstr.push_str(delim);

                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                pos += len as usize;
            }
        }

        if !jumped {
            self.change_position(pos)?;
        }

        Ok(outstr)
    }

    pub fn write(&mut self, val: u8) -> Result<(), DnsErrors> {
        if self.pos >= 512 {
            return Err(DnsErrors::ByteContainerError);
        }
        self.list[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<(), DnsErrors> {
        self.write(val)?;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<u16, DnsErrors> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(val)
    }

    pub fn write_u32(&mut self, val: u32) -> Result<(), DnsErrors> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<(), DnsErrors> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x34 {
                return Err(DnsErrors::ByteContainerError);
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
    pub fn set(&mut self, pos: usize, val: u8) -> Result<(), DnsErrors> {
        self.list[pos] = val;

        Ok(())
    }
    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), DnsErrors> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}
