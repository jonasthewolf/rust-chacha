
use key::Key;

// Type of inner state of chacha
const INNER_STATE_SIZE : usize = 16;
type InnerState = [u32;INNER_STATE_SIZE];

// Type of nonce
const NONCE_LENGTH : usize = 3;
pub type Nonce = [u32;NONCE_LENGTH];

// Alias for generated keystream block
type KeyStreamBlock = [u8;INNER_STATE_SIZE * 4];

// Index of block number
const BLOCK_NUMBER_INDEX : usize = 12;


// Structure for chacha algorithm
pub struct Chacha {
	// The state
	state : InnerState
}

impl Chacha {
	pub fn new(k : Key, n : Nonce) -> Chacha {
		Chacha {
			state : [ 0x65787061u32.to_le(),
			          0x6e642033u32.to_le(),
			          0x322d6279u32.to_le(),
			          0x7465206bu32.to_le(),
					  k.get_key_bits()[0].to_le(),
					  k.get_key_bits()[1].to_le(),
					  k.get_key_bits()[2].to_le(),
					  k.get_key_bits()[3].to_le(),
					  0, 0, 0, 0 /* BN */, n[0], n[1], n[2], 0 ],
		}
	}

	pub fn print_state(&self) {
		println!("{:?}", self.state);
	}
    /**
     * Generates a block of key stream for the given block number
     *
     * Params:
     *   keystream = at least 64 bytes of memory for the generated key stream
     *   blocknumber = the blocknumber to generate the keystream for
     *
     */
	pub fn get_keystream(&mut self, keystream : &mut KeyStreamBlock, blocknumber : u32) {
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
		for i in 0..16 {
			self.state[i] = self.state[i].overflowing_add(working_state[i]).0;
			keystream[i*4 + 0] = ((working_state[i] & 0xff000000) >> 24) as u8;
			keystream[i*4 + 1] = ((working_state[i] & 0x00ff0000) >> 16) as u8;
			keystream[i*4 + 2] = ((working_state[i] & 0x0000ff00) >> 8) as u8;
			keystream[i*4 + 3] = ((working_state[i] & 0x000000ff)) as u8;
		}
	
		println!("after  {:?} ", self.state.iter()
                        	  .map(|b| format!("{:02X}", b))
							  .collect::<Vec<_>>()
							  .join(" "));

	}
/*
	fn get_next_keystream(&mut self, keystream : keystream_block) {
		return self.get_keystream(keystream, self.state[BLOCK_NUMBER_INDEX
	] + 1);
	}
*/	
    /** Resets the block number to zero. */
	pub fn reset_block_counter(&mut self) {
		self.state[BLOCK_NUMBER_INDEX] = 0;
	}

    /** Copies the key into the state. */
	//pub fn set_key(&mut self,  usedkey : [u8;256/8]) {
	//	for i in usedkey.iter() {
	//		self.state[4 + i] = usedkey[i];
	//    }
	//}

    /** 
     * Performs a quarter round of chacha. 
     * 
     * Params:
     *  state = current working state for a block number
     *  a, b, c, d = constant of algorithm
     *
     */
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
