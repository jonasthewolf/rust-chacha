

// Type of inner state of chacha
const INNER_STATE_SIZE : usize = 16;
type InnerState = [u32;INNER_STATE_SIZE];


const NONCE_LENGTH : usize = 3;
// Type of nonce
pub type Nonce = [u32;NONCE_LENGTH];

// Index of block number
const BLOCK_NUMBER_INDEX : usize = 12;

// Structure for chacha algorithm
pub struct Chacha {
	// The state
	state : InnerState
}

impl Chacha {
	pub fn new(k : &Vec<u8>, n : &Nonce) -> Chacha {
		assert!(k.len() == 32);
		Chacha {
			state : [ 0x61707865u32.to_le(), 
					  0x3320646eu32.to_le(), 
					  0x79622d32u32.to_le(),
					  0x6b206574u32.to_le(),
					  ((k[0]  as u32) | ((k[1]  as u32) << 8) | ((k[2]  as u32) << 16) | ((k[3]  as u32) << 24)),
					  ((k[4]  as u32) | ((k[5]  as u32) << 8) | ((k[6]  as u32) << 16) | ((k[7]  as u32) << 24)),
					  ((k[8]  as u32) | ((k[9]  as u32) << 8) | ((k[10] as u32) << 16) | ((k[11] as u32) << 24)),
					  ((k[12] as u32) | ((k[13] as u32) << 8) | ((k[14] as u32) << 16) | ((k[15] as u32) << 24)),
					  ((k[16] as u32) | ((k[17] as u32) << 8) | ((k[18] as u32) << 16) | ((k[19] as u32) << 24)),
					  ((k[20] as u32) | ((k[21] as u32) << 8) | ((k[22] as u32) << 16) | ((k[23] as u32) << 24)),
					  ((k[24] as u32) | ((k[25] as u32) << 8) | ((k[26] as u32) << 16) | ((k[27] as u32) << 24)),
					  ((k[28] as u32) | ((k[29] as u32) << 8) | ((k[30] as u32) << 16) | ((k[31] as u32) << 24)),
					  0 /* BN */, 
					  n[0].to_le(),
					  n[1].to_le(),
					  n[2].to_le() ],
		}
	}

	fn _print_state(&self) {
		let mut keystream = [0u8;INNER_STATE_SIZE * 4];
		for i in 0..INNER_STATE_SIZE {
			keystream[i*4 + 0] = ((self.state[i] & 0x000000ff)) as u8;
			keystream[i*4 + 1] = ((self.state[i] & 0x0000ff00) >> 8) as u8;
			keystream[i*4 + 2] = ((self.state[i] & 0x00ff0000) >> 16) as u8;
			keystream[i*4 + 3] = ((self.state[i] & 0xff000000) >> 24) as u8;
		}
		println!("state  {:?} ", keystream.iter()
                        	  .map(|b| format!("{:02X}", b.to_le()))
							  .collect::<Vec<_>>()
							  .join(" "));		
	}

    /// Generates a block of key stream for the given block number
    //
    // Params:
    //   keystream = at least 64 bytes of memory for the generated key stream
    //   blocknumber = the blocknumber to generate the keystream for
    //
	pub fn get_keystream(&mut self, keystream : &mut [u8], blocknumber : u32) {
		assert!(keystream.len() == INNER_STATE_SIZE * 4);
		self.state[BLOCK_NUMBER_INDEX] = blocknumber;
		let mut working_state = self.state.clone();
		for _ in 0 .. 20/2 {
			Chacha::quarter_round(&mut working_state, 0, 4, 8, 12);
			Chacha::quarter_round(&mut working_state, 1, 5, 9, 13);
			Chacha::quarter_round(&mut working_state, 2, 6, 10, 14);
			Chacha::quarter_round(&mut working_state, 3, 7, 11, 15);
			Chacha::quarter_round(&mut working_state, 0, 5, 10, 15);
			Chacha::quarter_round(&mut working_state, 1, 6, 11, 12);
			Chacha::quarter_round(&mut working_state, 2, 7, 8, 13);
			Chacha::quarter_round(&mut working_state, 3, 4, 9, 14);
		}
		for i in 0..INNER_STATE_SIZE {
			working_state[i] = working_state[i].overflowing_add(self.state[i]).0;
			keystream[i*4 + 0] = ((working_state[i] & 0x000000ff)) as u8;
			keystream[i*4 + 1] = ((working_state[i] & 0x0000ff00) >> 8) as u8;
			keystream[i*4 + 2] = ((working_state[i] & 0x00ff0000) >> 16) as u8;
			keystream[i*4 + 3] = ((working_state[i] & 0xff000000) >> 24) as u8;
		}
	}

	
	pub fn get_next_keystream(&mut self, keystream : &mut [u8]) {
		let bn = self.state[BLOCK_NUMBER_INDEX];
		return self.get_keystream(keystream, bn + 1);
	}
	
    /// Resets the block number to zero. 
	pub fn reset_block_counter(&mut self) {
		self.state[BLOCK_NUMBER_INDEX] = 0;
	}


    /// Performs a quarter round of chacha. 
    // 
    // Params:
    //  state = current working state for a block number
    //  a, b, c, d = constant of algorithm
    //
	fn quarter_round(state : &mut InnerState, a : usize, b : usize, c : usize, d : usize) {
		state[a] = state[a].overflowing_add(state[b]).0;
		state[d] ^= state[a];
		state[d] = state[d].rotate_left(16);
		state[c] = state[c].overflowing_add(state[d]).0;
		state[b] ^= state[c];
		state[b] = state[b].rotate_left(12);
		state[a] = state[a].overflowing_add(state[b]).0;
		state[d] ^= state[a];
		state[d] = state[d].rotate_left(8);
		state[c] = state[c].overflowing_add(state[d]).0;
		state[b] ^= state[c];
		state[b] = state[b].rotate_left(7);
    }

	
}
