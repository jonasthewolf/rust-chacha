
pub const KEY_LENGTH : usize = 256/8;
pub type KeyWordSize = [u32;KEY_LENGTH/4];
// Key length in byte
pub struct Key([u32;KEY_LENGTH/4]);

impl Key {
	pub fn new(inkey : [u8;KEY_LENGTH]) -> Key {
        let mut k = Key([0;KEY_LENGTH/4]);
		for i in 0 .. KEY_LENGTH-4 {
			k.0[i/4] = (((inkey[i+0] as u32) << 24) | ((inkey[i+1] as u32) << 16) | ((inkey[i+2] as u32) << 8) | ((inkey[i+3] as u32) << 0)) as u32;
			//k.0[i/4] = as_le([inkey[i], inkey[i+1], inkey[i+2], inkey[i+3]]);
		}
        return k;
    }
	pub fn get_key_bits(&self) -> &KeyWordSize { 
		return &self.0; 
	}
	pub fn get_key_length(&self) -> usize { 
		return self.0.len(); 
	}
}


